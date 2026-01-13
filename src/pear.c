#include <appling.h>
#include <appling/os.h>
#include <assert.h>
#include <ctype.h>
#include <stdlib.h>
#include <fx.h>
#include <js.h>
#include <log.h>
#include <path.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <uv.h>

#if defined(APPLING_OS_LINUX)
#include <libgen.h>
#include <unistd.h>
#endif

#include "../include/pear.h"

static uv_thread_t pear__thread;
static uv_process_t pear__process;

static fx_window_t *pear__window;

static appling_link_t pear__app_link;
static appling_lock_t pear__lock;
static const char *pear__path;
static appling_resolve_t pear__resolve;
static appling_bootstrap_t pear__bootstrap;
static uint64_t pear__bootstrap_start;

static int
pear__scandir_first_dir(const char *path, char *name, size_t name_len) {
  uv_fs_t req;
  int res = uv_fs_scandir(uv_default_loop(), &req, path, 0, NULL);
  if (res < 0) return res;

  uv_dirent_t ent;
  while (uv_fs_scandir_next(&req, &ent) != UV_EOF) {
    if (ent.type == UV_DIRENT_DIR) {
      strncpy(name, ent.name, name_len - 1);
      name[name_len - 1] = '\0';
      uv_fs_req_cleanup(&req);
      return 0;
    }
  }

  uv_fs_req_cleanup(&req);
  return UV_ENOENT;
}

static int
pear__scandir_max_fork(const char *path, char *name, size_t name_len) {
  uv_fs_t req;
  int res = uv_fs_scandir(uv_default_loop(), &req, path, 0, NULL);
  if (res < 0) return res;

  long best = -1;
  uv_dirent_t ent;
  while (uv_fs_scandir_next(&req, &ent) != UV_EOF) {
    if (ent.type != UV_DIRENT_DIR) continue;
    const char *s = ent.name;
    if (!isdigit((unsigned char) s[0])) continue;
    char *end = NULL;
    long val = strtol(s, &end, 10);
    if (end == s || *end != '\0') continue;
    if (val > best) {
      best = val;
      strncpy(name, ent.name, name_len - 1);
      name[name_len - 1] = '\0';
    }
  }

  uv_fs_req_cleanup(&req);
  return (best >= 0) ? 0 : UV_ENOENT;
}

static int
pear__resolve_platform_fallback(appling_path_t out_path, size_t *out_len) {
  if (pear__path == NULL || pear__path[0] == '\0') return UV_EINVAL;

  appling_path_t by_dkey;
  size_t len = sizeof(appling_path_t);
  path_join((const char *[]) {pear__path, "by-dkey", NULL}, by_dkey, &len, path_behavior_system);

  char dkey[256];
  int err = pear__scandir_first_dir(by_dkey, dkey, sizeof(dkey));
  if (err < 0) return err;

  appling_path_t dkey_path;
  len = sizeof(appling_path_t);
  path_join((const char *[]) {by_dkey, dkey, NULL}, dkey_path, &len, path_behavior_system);

  char fork_dir[64];
  err = pear__scandir_max_fork(dkey_path, fork_dir, sizeof(fork_dir));
  if (err < 0) return err;

  path_join(
    (const char *[]) {dkey_path, fork_dir, "by-arch", APPLING_TARGET, NULL},
    out_path,
    out_len,
    path_behavior_system
  );

  return 0;
}

#if defined(APPLING_OS_WIN32)
static void pear__log_bootstrap(const char *tag, const char *detail);
static void
pear__log_stat(const char *tag, const char *path) {
  uv_fs_t req;
  int rc = uv_fs_stat(uv_default_loop(), &req, path, NULL);
  if (rc < 0) {
    char buf[128];
    snprintf(buf, sizeof(buf), "missing(%d) %s", rc, path);
    pear__log_bootstrap(tag, buf);
  } else {
    pear__log_bootstrap(tag, path);
  }
  uv_fs_req_cleanup(&req);
}
#endif
static bool pear__needs_bootstrap;

#if defined(APPLING_OS_WIN32)
static void
pear__log_bootstrap(const char *tag, const char *detail) {
  if (pear__path == NULL || pear__path[0] == '\0') return;

  appling_path_t log_path;
  size_t log_path_len = sizeof(appling_path_t);
  int err = path_join(
    (const char *[]) {pear__path, "bootstrap.log", NULL},
    log_path,
    &log_path_len,
    path_behavior_system
  );
  if (err != 0) return;

  FILE *fp = fopen(log_path, "a");
  if (!fp) return;

  uint64_t ts = uv_hrtime();
  fprintf(fp, "[%llu] %s: %s\n",
    (unsigned long long) ts,
    tag ? tag : "event",
    detail ? detail : ""
  );
  fclose(fp);
}
#endif

static appling_platform_t pear__platform = {
  .key = {0x6d, 0xd8, 0x97, 0x2d, 0xb0, 0x87, 0xad, 0x75, 0x41, 0x9a, 0x0b, 0x55, 0x4f, 0x6e, 0xa1, 0xfb, 0x22, 0x22, 0x3b, 0xa1, 0xf2, 0xc4, 0x84, 0x54, 0x41, 0xe0, 0x78, 0x8a, 0xf3, 0x0e, 0xf3, 0x7d},
  .length = 2392,
};

static appling_app_t pear__app;
static const char *pear__app_name;

static bool
pear__is_hex_id(const char *id, size_t len) {
  for (size_t i = 0; i < len; i++) {
    char c = id[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }

  return true;
}

static bool
pear__is_z32_id(const char *id, size_t len) {
  // z-base-32 alphabet used by hypercore IDs
  static const char *alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769";

  for (size_t i = 0; i < len; i++) {
    char c = id[i];
    const char *p = alphabet;
    bool found = false;

    while (*p) {
      if (*p == c) {
        found = true;
        break;
      }
      p++;
    }

    if (!found) return false;
  }

  return true;
}

static bool
pear__is_valid_id(const char *id) {
  size_t len = strlen(id);

  if (len == 64) return pear__is_hex_id(id, len);
  if (len == 52) return pear__is_z32_id(id, len);

  return false;
}

static void
pear__on_close(fx_t *fx, void *data) {
  int err;

  err = fx_close_window(pear__window);
  assert(err == 0);

#if PEAR_RESTART_AFTER_BOOTSTRAP
  err = appling_open(&pear__app, NULL);
  assert(err == 0);
#endif
}

static void
pear__on_unlock_after_bootstrap(appling_lock_t *req, int status) {
  int err;

  assert(status == 0);

  uint64_t elapsed = uv_hrtime() - pear__bootstrap_start;

  elapsed /= 1e6;

  if (elapsed < 5000) uv_sleep(5000 - elapsed);

  err = fx_dispatch(pear__on_close, NULL);
  assert(err == 0);
}

static void
pear__on_resolve_after_bootstrap(appling_resolve_t *req, int status) {
  int err;

#if defined(APPLING_OS_WIN32)
  if (status != 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "status=%d", status);
    pear__log_bootstrap("resolve", buf);
  }
#endif

#if defined(APPLING_OS_WIN32)
  if (status == UV_ENOENT) {
    appling_path_t fallback;
    size_t fallback_len = sizeof(appling_path_t);
    if (pear__resolve_platform_fallback(fallback, &fallback_len) == 0) {
      strncpy(pear__platform.path, fallback, sizeof(pear__platform.path) - 1);
      pear__platform.path[sizeof(pear__platform.path) - 1] = '\0';
      pear__log_bootstrap("resolve-fallback", pear__platform.path);
      pear__log_stat("platform-path", pear__platform.path);

      appling_path_t launch_path;
      size_t launch_len = sizeof(appling_path_t);
      path_join(
        (const char *[]) {pear__platform.path, "lib", appling_platform_entry, NULL},
        launch_path,
        &launch_len,
        path_behavior_system
      );
      pear__log_stat("platform-entry", launch_path);

      err = appling_preflight(&pear__platform, &pear__app_link);
      assert(err == 0);

      err = appling_unlock(req->loop, &pear__lock, pear__on_unlock_after_bootstrap);
      assert(err == 0);
      return;
    }
  }
#endif

  assert(status == 0);

  err = appling_preflight(&pear__platform, &pear__app_link);
  assert(err == 0);

  err = appling_unlock(req->loop, &pear__lock, pear__on_unlock_after_bootstrap);
  assert(err == 0);
}

static void
pear__on_bootstrap(appling_bootstrap_t *req, int status) {
  int err;

#if defined(APPLING_OS_WIN32)
  if (status == 0) {
    pear__log_bootstrap("bootstrap", "ok");
  } else {
    pear__log_bootstrap("bootstrap", req->error);
  }
#endif

  if (status == 0) {
    err = appling_resolve(req->loop, &pear__resolve, pear__path, &pear__platform, pear__on_resolve_after_bootstrap);
    assert(err == 0);
  } else {
    log_fatal("%s", req->error);

    err = appling_unlock(req->loop, &pear__lock, pear__on_unlock_after_bootstrap);
    assert(err == 0);
  }
}

static void
pear__on_thread(void *data) {
  int err;

  pear__bootstrap_start = uv_hrtime();

  uv_loop_t loop;
  err = uv_loop_init(&loop);
  assert(err == 0);

  if (pear__needs_bootstrap) {
    js_platform_t *js;
    err = js_create_platform(&loop, NULL, &js);
    assert(err == 0);

    err = appling_bootstrap(&loop, js, &pear__bootstrap, pear__platform.key, pear__path, pear__on_bootstrap);
    assert(err == 0);

    err = uv_run(&loop, UV_RUN_DEFAULT);
    assert(err == 0);

    err = js_destroy_platform(js);
    assert(err == 0);
  } else {
    err = appling_resolve(&loop, &pear__resolve, pear__path, &pear__platform, pear__on_resolve_after_bootstrap);
    assert(err == 0);
  }

  err = uv_run(&loop, UV_RUN_DEFAULT);
  assert(err == 0);

  err = uv_loop_close(&loop);
  assert(err == 0);
}

static void
pear__on_launch(fx_t *fx) {
  int err;

  err = uv_thread_create(&pear__thread, pear__on_thread, NULL);
  assert(err == 0);

  fx_image_t *image;
  err = fx_image_init(fx, 0, 0, 400, 400, &image);
  assert(err == 0);

  appling_path_t image_path;
  size_t image_path_len = sizeof(appling_path_t);

#if defined(APPLING_OS_LINUX)
  char flatpak_path[256];
  snprintf(flatpak_path, sizeof(flatpak_path), "%s%s%s", "../share/", basename(pear__app.path), "/splash.png");
#endif

  err = path_join(
    (const char *[]) {
      pear__app.path,
#if defined(APPLING_OS_LINUX)
      access("/.flatpak-info", F_OK) == 0 ? flatpak_path : "../../../splash.png",
#elif defined(APPLING_OS_DARWIN)
      "../../Resources/splash.png",
#elif defined(APPLING_OS_WIN32)
      "../splash.png",
#else
#error Unsupported operating system
#endif
      NULL,
    },
    image_path,
    &image_path_len,
    path_behavior_system
  );
  assert(err == 0);

  err = fx_image_load_file(image, image_path, image_path_len);
  assert(err == 0);

  fx_view_t *view;
  err = fx_view_init(fx, 0, 0, 400, 400, &view);
  assert(err == 0);

  err = fx_set_child((fx_node_t *) view, (fx_node_t *) image, 0);
  assert(err == 0);

  fx_screen_t *screen;
  err = fx_get_main_screen(fx, &screen);
  assert(err == 0);

  float width, height;
  err = fx_get_screen_bounds(screen, NULL, NULL, &width, &height);
  assert(err == 0);

  err = fx_screen_release(screen);
  assert(err == 0);

  err = fx_window_init(fx, view, (width - 400) / 2, (height - 400) / 2, 400, 400, fx_window_no_frame, &pear__window);
  assert(err == 0);

  err = fx_set_window_title(pear__window, "Installing app", -1);
  assert(err == 0);

  err = fx_activate_window(pear__window);
  assert(err == 0);
}

static void
pear__on_unlock_before_bootstrap(appling_lock_t *req, int status) {
  int err;

  assert(status == 0);

  err = appling_launch(&pear__platform, &pear__app, &pear__app_link, pear__app_name);
#if defined(APPLING_OS_WIN32)
  if (err < 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "launch=%d", err);
    pear__log_bootstrap("launch-error", buf);
  }
#endif
  assert(err == 0);
}

static void
pear__on_resolve_before_bootstrap(appling_resolve_t *req, int status) {
  int err;

#if defined(APPLING_OS_WIN32)
  if (status == UV_ENOENT) {
    appling_path_t fallback;
    size_t fallback_len = sizeof(appling_path_t);
    if (pear__resolve_platform_fallback(fallback, &fallback_len) == 0) {
      strncpy(pear__platform.path, fallback, sizeof(pear__platform.path) - 1);
      pear__platform.path[sizeof(pear__platform.path) - 1] = '\0';
      pear__log_bootstrap("resolve-fallback", pear__platform.path);
      status = 0;
    }
  }
#endif

  int ready = -1;
  if (status == 0) ready = appling_ready(&pear__platform, &pear__app_link);

#if defined(APPLING_OS_WIN32)
  if (status == 0 && ready != 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "ready=%d", ready);
    pear__log_bootstrap("ready", buf);
  }
#endif

  if (status == 0 && ready >= 0) {
    err = appling_unlock(req->loop, &pear__lock, pear__on_unlock_before_bootstrap);
  } else {
    pear__needs_bootstrap = status != 0 || ready < 0;

    fx_t *fx;
    err = fx_init(req->loop, &fx);
    assert(err == 0);

    err = fx_run(fx, pear__on_launch, NULL);
    assert(err == 0);

    err = uv_thread_join(&pear__thread);
    assert(err == 0);
  }

  assert(err == 0);
}

static void
pear__on_lock(appling_lock_t *req, int status) {
  int err;

  assert(status == 0);

  err = appling_resolve(req->loop, &pear__resolve, pear__path, &pear__platform, pear__on_resolve_before_bootstrap);
  assert(err == 0);
}

const char *pear_path = NULL;

int
pear_launch(int argc, char *argv[], pear_id_t id, const char *name) {
  int err;

  pear__app_name = name;

  argv = uv_setup_args(argc, argv);

  err = log_open(name, 0);
  assert(err == 0);

  size_t path_len = sizeof(appling_path_t);

  err = uv_exepath(pear__app.path, &path_len);
  assert(err == 0);

  memcpy(&pear__app.id, id, sizeof(appling_id_t));

  if (argc > 1 &&
      appling_parse(argv[1], &pear__app_link) == 0 &&
      pear__is_valid_id(pear__app_link.id)) {
    // Parsed a valid pear:// or punch:// link with a valid key.
  } else {
    // macOS launches can pass non-link argv (e.g. -psn_...). Fall back to app ID.
    memcpy(&pear__app_link.id, pear__app.id, sizeof(appling_id_t));
    pear__app_link.data[0] = '\0';
  }

  pear__path = pear_path; // Default platform directory

#if defined(APPLING_OS_WIN32)
  pear__log_bootstrap("launch", pear__path);
  appling_path_t log_path;
  size_t log_path_len = sizeof(appling_path_t);
  if (path_join(
    (const char *[]) {pear__path, "bootstrap.log", NULL},
    log_path,
    &log_path_len,
    path_behavior_system
  ) == 0) {
    uv_os_setenv("PEAR_BOOTSTRAP_LOG", log_path);
  }
#endif

#if defined(APPLING_OS_LINUX)
  if (getenv("SNAP_USER_COMMON") != NULL) {
    appling_path_t snap_path;
    size_t snap_path_len = sizeof(appling_path_t);

    err = path_join(
      (const char *[]) {
        getenv("SNAP_USER_COMMON"),
        "pear",
        NULL
      },
      snap_path,
      &snap_path_len,
      path_behavior_system
    );
    assert(err == 0);

    pear__path = strdup(snap_path);
  }
#endif

  err = appling_lock(uv_default_loop(), &pear__lock, pear__path, pear__on_lock);
  assert(err == 0);

  err = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  assert(err == 0);

  err = uv_loop_close(uv_default_loop());
  assert(err == 0);

  return 0;
}
