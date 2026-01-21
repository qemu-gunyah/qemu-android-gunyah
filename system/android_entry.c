// android_entry.c
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <android/log.h>

#define LOG_TAG "Lib QEMU"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#include "qemu/osdep.h"
#include "qemu-main.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "system/replay.h"
#include "system/system.h"

extern int (*qemu_main)(void);

typedef struct {
    int fd;
} LogThreadArgs;

static void *qemu_default_main(void *opaque)
{
    int status;

    replay_mutex_lock();
    bql_lock();
    status = qemu_main_loop();
    qemu_cleanup(status);
    bql_unlock();
    replay_mutex_unlock();

    exit(status);
}

static void *logcat_thread_fn(void *arg) {
    LogThreadArgs *a = (LogThreadArgs *)arg;
    int fd = a->fd;
    free(a);

    char buf[512];
    ssize_t n;

    // keep reading forever; handle EAGAIN by sleeping a bit
    for (;;) {
        n = read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = 0;
            __android_log_write(ANDROID_LOG_INFO, LOG_TAG, buf);
        } else {
            // non-blocking pipe: no data or temporary condition
            usleep(10 * 1000); // 10ms
        }
    }
    return NULL;
}

// Wrapper for JNI call
__attribute__((visibility("default")))
int android_qemu_start(int argc, char **argv) {
    int pipefd[2];
    if (pipe(pipefd) == 0) {
        fcntl(pipefd[0], F_SETFL, O_NONBLOCK);
        fcntl(pipefd[1], F_SETFL, O_NONBLOCK);

        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        pthread_t log_thread;
        LogThreadArgs *a = (LogThreadArgs *)malloc(sizeof(*a));
        a->fd = pipefd[0];

        pthread_create(&log_thread, NULL, logcat_thread_fn, a);
        pthread_detach(log_thread);
    }

    LOGI("Starting QEMU...");
    LOGI("android_qemu_start argv dump:");
    for (int i = 0; i < argc; i++) {
        LOGI("  argv[%d] = '%s'", i, argv[i] ? argv[i] : "(null)");
    }

    qemu_init(argc, argv);
    bql_unlock();
    replay_mutex_unlock();

    if (qemu_main) {
        QemuThread main_loop_thread;
        qemu_thread_create(&main_loop_thread, "qemu_main",
                           qemu_default_main, NULL, QEMU_THREAD_DETACHED);
        int ret = qemu_main();
        LOGI("QEMU exited with code %d", ret);
        return ret;
    } else {
        /* Never returns (calls exit). */
        qemu_default_main(NULL);
        __builtin_unreachable();
    }
}

static pid_t g_qemu_pid = -1;

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_startQemu(JNIEnv *env, jclass clazz, jobjectArray jargs) {
    (void)clazz;

    int argc = (*env)->GetArrayLength(env, jargs);
    LOGI("Jni Starting QEMU... argc=%d", argc);

    // Build argv (NULL-terminated)
    char **argv = (char **)malloc(sizeof(char*) * (argc + 1));
    if (!argv) {
        LOGE("malloc argv failed");
        return;
    }

    for (int i = 0; i < argc; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, jargs, i);
        const char *str = (*env)->GetStringUTFChars(env, js, 0);
        argv[i] = strdup(str);
        (*env)->ReleaseStringUTFChars(env, js, str);
        (*env)->DeleteLocalRef(env, js);

        if (!argv[i]) {
            LOGE("strdup failed at arg %d", i);
            // cleanup what we already allocated
            for (int j = 0; j < i; j++) {
                free(argv[j]);
            }
            free(argv);
            return;
        }
    }
    argv[argc] = NULL;
    LOGI("JNI argv dump:");
    for (int i = 0; i < argc; i++) {
        LOGI("  argv[%d] = '%s'", i, argv[i] ? argv[i] : "(null)");
    }

    // Fork and run QEMU in the child process
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("fork failed");
        for (int i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);
        return;
    }

    if (pid == 0) {
        // Child: run QEMU (this will typically block for the VM lifetime)
        LOGI("QEMU child process started");
        int ret = android_qemu_start(argc, argv);

        for (int i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);

        _exit(ret);
    }

    // Parent: free argv and return to Java immediately
    g_qemu_pid = pid;
    LOGI("QEMU forked pid=%d", (int)pid);

    for (int i = 0; i < argc; i++) {
        free(argv[i]);
    }
    free(argv);
}