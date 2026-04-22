#ifdef __cplusplus
extern "C" {
#endif

void log_attack_event(
    const char *timestamp,
    const char *actor,
    const char *type,
    const char *description
);

#ifdef __cplusplus
}
#endif
