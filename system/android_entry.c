// android_entry.c
#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

// #define LOG_TAG "QEMU"
// #define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
// #define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern int qemu_main(int argc, char **argv);

typedef struct {
    int fd;
} LogThreadArgs;

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
            //__android_log_write(ANDROID_LOG_INFO, LOG_TAG, buf);
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

    //LOGI("Starting QEMU...");
    int ret = qemu_main(argc, argv);
    //LOGI("QEMU exited with code %d", ret);
    return ret;
}

typedef struct {
    int argc;
    char **argv;
} QemuArgs;

static void *qemu_thread_fn(void *arg) {
    QemuArgs *qa = (QemuArgs *)arg;
    android_qemu_start(qa->argc, qa->argv);

    for (int i = 0; i < qa->argc; i++) free(qa->argv[i]);
    free(qa->argv);
    free(qa);
    return NULL;
}

JNIEXPORT void JNICALL
Java_com_vectras_qemu_jni_Loader_startQemu(JNIEnv *env, jclass clazz, jobjectArray jargs) {
    (void)clazz;

    int argc = (*env)->GetArrayLength(env, jargs);

    QemuArgs *qa = (QemuArgs *)malloc(sizeof(QemuArgs));
    qa->argc = argc;
    qa->argv = (char **)malloc(sizeof(char*) * argc);

    for (int i = 0; i < argc; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, jargs, i);
        const char *str = (*env)->GetStringUTFChars(env, js, 0);
        qa->argv[i] = strdup(str);
        (*env)->ReleaseStringUTFChars(env, js, str);
        (*env)->DeleteLocalRef(env, js);
    }

    pthread_t thread;
    pthread_create(&thread, NULL, qemu_thread_fn, qa);
    pthread_detach(thread);
}