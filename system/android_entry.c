// android_entry.c
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <android/log.h>
#include <stdbool.h>

#include "qemu/osdep.h"
#include "qemu-main.h"
#include "qemu/main-loop.h"
#include "system/replay.h"
#include "system/system.h"

static JavaVM *g_vm = NULL;
static jobject g_log_callback = NULL; // GlobalRef

enum {
    QEMU_LOG_STDOUT = 1,
    QEMU_LOG_STDERR = 2,
};

static const char *kLogTag = "QEMU-OUT";

static int g_forward_fd = -1;
static pthread_mutex_t g_forward_fd_lock = PTHREAD_MUTEX_INITIALIZER;

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
            (void)write(outfd, prefix, (size_t)strlen(prefix));
            (void)write(outfd, buf, (size_t)strlen(buf));
        } else {
            __android_log_print(level, kLogTag, "%s", buf);
        }
    }
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
    setup_stdio_pipes();

    /* QEMU upstream main.c (Android-friendly path): */
    qemu_init(argc, argv);
    bql_unlock();
    replay_mutex_unlock();

    /*
     * IMPORTANT: Run the QEMU main loop on THIS thread.
     * Do not spawn another thread here, otherwise qemu_in_main_thread()
     * assertions can trip in subsystems that must execute on the main thread.
     */
    int status;
    replay_mutex_lock();
    bql_lock();
    status = qemu_main_loop();
    qemu_cleanup(status);
    bql_unlock();
    replay_mutex_unlock();

    // qemu_main_loop() only returns on exit
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

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    set_forward_fd(-1);
}