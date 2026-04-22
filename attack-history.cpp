#include "attack-history.h"
#include "attack-history-db.cpp"
#include <string>

void log_attack_event(
    const char *timestamp,
    const char *actor,
    const char *type,
    const char *description
) {
    AttackEvent ev;
    ev.timestamp = timestamp;
    ev.actor = actor;
    ev.type = type;
    ev.description = description;

    logAttackEvent(ev);   // calls original function
}
