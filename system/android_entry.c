// android_entry.c
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "qemu/osdep.h"
#include "qemu-main.h"
#include "qemu/main-loop.h"
#include "system/replay.h"
#include "system/system.h"
#include "system/runstate.h"

#include <sys/ucontext.h>
#include <stddef.h>

static JavaVM *g_vm = NULL;
static jobject g_log_callback = NULL; // GlobalRef

enum {
    QEMU_LOG_STDOUT = 1,
    QEMU_LOG_STDERR = 2,
};

#include <android/log.h>
static const char *kLogTag = "QEMU-OUT";
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, kLogTag, __VA_ARGS__)

static int g_forward_fd = -1;
static pthread_mutex_t g_forward_fd_lock = PTHREAD_MUTEX_INITIALIZER;

static char *g_resolv_conf_path = NULL;
static pthread_mutex_t g_resolv_conf_lock = PTHREAD_MUTEX_INITIALIZER;

__attribute__((visibility("default")))
const char *android_get_resolv_conf_path(void) {
    pthread_mutex_lock(&g_resolv_conf_lock);
    const char *p = g_resolv_conf_path;
    pthread_mutex_unlock(&g_resolv_conf_lock);
    return p;
}

static int get_forward_fd(void) {
    pthread_mutex_lock(&g_forward_fd_lock);
    int fd = g_forward_fd;
    pthread_mutex_unlock(&g_forward_fd_lock);
    return fd;
}

static void set_forward_fd(int fd) {
    pthread_mutex_lock(&g_forward_fd_lock);
    if (g_forward_fd >= 0) {
        close(g_forward_fd);
        g_forward_fd = -1;
    }
    if (fd >= 0) {
        g_forward_fd = dup(fd);
    }
    pthread_mutex_unlock(&g_forward_fd_lock);
}


typedef struct {
    int fd;
    int level;
} LogThreadArgs;

static void *log_reader_thread_fn(void *arg) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    pthread_t self = pthread_self();

    __android_log_print(
        ANDROID_LOG_WARN,
        "QEMU-PTHREAD",
        "log_reader_thread start: tid=%d pthread=%p",
        tid,
        (void *)self
    );

    LogThreadArgs *a = (LogThreadArgs *)arg;
    int fd = a->fd;
    int level = a->level;
    free(a);

    char buf[1024];
    while (1) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = 0;

        int outfd = get_forward_fd();
        if (outfd >= 0) {
            const char *prefix = (level == QEMU_LOG_STDERR) ? "[E] " : "[O] ";
            write(outfd, prefix, strlen(prefix));
            write(outfd, buf, strlen(buf));
        } else {
            __android_log_print(level, kLogTag, "%s", buf);
        }
    }

    __android_log_print(
        ANDROID_LOG_WARN,
        "QEMU-PTHREAD",
        "log_reader_thread exit: tid=%d",
        tid
    );

    close(fd);
    return NULL;
}

static void setup_stdio_pipes(void) {
    int out_pipe[2];
    int err_pipe[2];

    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        return;
    }

    dup2(out_pipe[1], STDOUT_FILENO);
    dup2(err_pipe[1], STDERR_FILENO);

    close(out_pipe[1]);
    close(err_pipe[1]);

    pthread_t t1, t2;

    LogThreadArgs *a1 = malloc(sizeof(*a1));
    a1->fd = out_pipe[0];
    a1->level = QEMU_LOG_STDOUT;
    pthread_create(&t1, NULL, log_reader_thread_fn, a1);
    pthread_detach(t1);

    LogThreadArgs *a2 = malloc(sizeof(*a2));
    a2->fd = err_pipe[0];
    a2->level = QEMU_LOG_STDERR;
    pthread_create(&t2, NULL, log_reader_thread_fn, a2);
    pthread_detach(t2);
}

__attribute__((visibility("default")))
int android_qemu_start(int argc, char **argv) {

    __android_log_print( ANDROID_LOG_WARN, "QEMU-system", "PAGE_SIZE=%ld\n", sysconf(_SC_PAGESIZE));

    qemu_thread_init_tls();

    setup_stdio_pipes();
    /*
     * IMPORTANT: Run the QEMU main loop on THIS thread.
     * Do not spawn another thread here, otherwise qemu_in_main_thread()
     * assertions can trip in subsystems that must execute on the main thread.
     */


    // LOGI("DIAG: sizeof(ucontext_t)=%zu\n", sizeof(ucontext_t));
    // LOGI("DIAG: uc_mcontext offset=%zu\n", offsetof(ucontext_t, uc_mcontext));
    // LOGI("DIAG: regs[0] offset=%zu\n", offsetof(ucontext_t, uc_mcontext.regs[0]));
    // LOGI("DIAG: sp offset=%zu\n", offsetof(ucontext_t, uc_mcontext.sp));
    // LOGI("DIAG: pc offset=%zu\n", offsetof(ucontext_t, uc_mcontext.pc));
    // LOGI("DIAG: pstate offset=%zu\n", offsetof(ucontext_t, uc_mcontext.pstate));
    // LOGI("DIAG: uc_stack offset=%zu\n", offsetof(ucontext_t, uc_stack));
    // LOGI("DIAG: uc_stack.ss_sp offset=%zu\n", offsetof(ucontext_t, uc_stack.ss_sp));
    // LOGI("DIAG: uc_stack.ss_size offset=%zu\n", offsetof(ucontext_t, uc_stack.ss_size));
    // LOGI("DIAG: uc_link offset=%zu\n", offsetof(ucontext_t, uc_link));
    // LOGI("DIAG: uc_sigmask offset=%zu\n", offsetof(ucontext_t, uc_sigmask));

    qemu_init(argc, argv); 
    bql_unlock();
    replay_mutex_unlock();
    int status;
    replay_mutex_lock();
    bql_lock();

    // qemu_main_loop() only returns on exit
    status = qemu_main_loop();
    qemu_cleanup(status);
    return status;
}

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_startQemu(JNIEnv *env, jclass clazz, jobjectArray jargs) {
    (void)clazz;

    int argc = (*env)->GetArrayLength(env, jargs);

    // Build argv (NULL-terminated)
    char **argv = (char **)malloc(sizeof(char*) * (argc + 1));
    if (!argv) {
        return;
    }

    for (int i = 0; i < argc; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, jargs, i);
        const char *str = (*env)->GetStringUTFChars(env, js, 0);
        argv[i] = strdup(str);
        (*env)->ReleaseStringUTFChars(env, js, str);
        (*env)->DeleteLocalRef(env, js);

        if (!argv[i]) {
            for (int j = 0; j < i; j++) {
                free(argv[j]);
            }
            free(argv);
            return;
        }
    }
    argv[argc] = NULL;

    /*
     * Run QEMU directly on the calling thread.
     * With android:process=":qemu", call this from that process main thread.
     */
    (void)android_qemu_start(argc, argv);

    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_setStdFd(JNIEnv *env, jclass clazz, jint fd) {
    (void)env;
    (void)clazz;
    // Duplicate the fd so Java can close its ParcelFileDescriptor independently.
    set_forward_fd((int)fd);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_vm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_setLogCallback(JNIEnv *env, jclass clazz, jobject callback) {
    (void)clazz;
    if (g_log_callback) {
        (*env)->DeleteGlobalRef(env, g_log_callback);
        g_log_callback = NULL;
    }
    if (callback) {
        g_log_callback = (*env)->NewGlobalRef(env, callback);
    }
}

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_setResolvConfPath(JNIEnv *env, jclass clazz, jstring path) {
    (void)clazz;
    pthread_mutex_lock(&g_resolv_conf_lock);
    free(g_resolv_conf_path);
    g_resolv_conf_path = NULL;
    if (path) {
        const char *str = (*env)->GetStringUTFChars(env, path, 0);
        if (str) {
            g_resolv_conf_path = strdup(str);
            __android_log_print(ANDROID_LOG_INFO, "QEMU-system",
                                "resolv.conf path set to: %s", g_resolv_conf_path);
            (*env)->ReleaseStringUTFChars(env, path, str);
        }
    }
    pthread_mutex_unlock(&g_resolv_conf_lock);
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    set_forward_fd(-1);
    pthread_mutex_lock(&g_resolv_conf_lock);
    free(g_resolv_conf_path);
    g_resolv_conf_path = NULL;
    pthread_mutex_unlock(&g_resolv_conf_lock);
}


/*
 * Clean shutdown — asks the guest to power off gracefully.
 * Equivalent to pressing the power button / ACPI shutdown.
 * qemu_main_loop() will return once the guest has shut down.
 */
JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_shutdownQemu(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    __android_log_print(ANDROID_LOG_INFO, "QEMU-system",
                        "stopQemu requested — scheduling shutdown");
    /*
     * qemu_system_shutdown_request() is safe to call from any thread.
     * It posts an event to the main loop which will cause
     * qemu_main_loop() to return cleanly, running qemu_cleanup().
     */
    qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_UI);
}

/*
 * Reboot — asks QEMU to reset the virtual machine.
 * The guest OS will restart as if the reset button was pressed.
 * QEMU itself keeps running; qemu_main_loop() does NOT return.
 */
JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_rebootQemu(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    __android_log_print(ANDROID_LOG_INFO, "QEMU-system",
                        "rebootQemu: requesting VM reset");
    qemu_system_reset_request(SHUTDOWN_CAUSE_HOST_UI);
}

/*
 * Force stop — immediately kills the QEMU process.
 * Use only as a last resort when clean shutdown hangs.
 * This is equivalent to pulling the power cord.
 */
JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_forceStopQemu(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;
    __android_log_print(ANDROID_LOG_WARN, "QEMU-system",
                        "forceStopQemu: killing process NOW");
    /*
     * _exit() terminates the process immediately without running
     * atexit handlers or flushing stdio. Since android:process=":qemu"
     * runs QEMU in a separate process, this only kills the QEMU process,
     * not the main app process.
     */
    _exit(0);
}