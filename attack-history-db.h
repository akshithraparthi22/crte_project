#ifndef ATTACK_HISTORY_DB_H
#define ATTACK_HISTORY_DB_H

struct AttackEvent {
    char timestamp[64];
    char actor[128];
    char type[128];
    char description[256];
};

void logAttackEvent(const char *timestamp,
                    const char *actor,
                    const char *type,
                    const char *description);

int readAttackHistory(struct AttackEvent *events, int maxEvents);

#endif
