#include "attack-history-db.h"
#include <stdio.h>
#include <string.h>

#define HISTORY_FILE "attack-history-db.txt"

void logAttackEvent(const char *timestamp,
                    const char *actor,
                    const char *type,
                    const char *description)
{
    FILE *f = fopen(HISTORY_FILE, "a");
    if (!f) return;

    fprintf(f, "%s|%s|%s|%s\n", timestamp, actor, type, description);
    fclose(f);
}

// returns number of events loaded
int readAttackHistory(struct AttackEvent *events, int maxEvents)
{
    FILE *f = fopen(HISTORY_FILE, "r");
    if (!f) return 0;

    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < maxEvents)
    {
        char *p1 = strchr(line, '|');
        if (!p1) continue;
        *p1 = '\0';

        char *p2 = strchr(p1 + 1, '|');
        if (!p2) continue;
        *p2 = '\0';

        char *p3 = strchr(p2 + 1, '|');
        if (!p3) continue;
        *p3 = '\0';

        strncpy(events[count].timestamp,  line,              sizeof(events[count].timestamp));
        strncpy(events[count].actor,      p1 + 1,            sizeof(events[count].actor));
        strncpy(events[count].type,       p2 + 1,            sizeof(events[count].type));
        strncpy(events[count].description,p3 + 1,            sizeof(events[count].description));

        // remove newline
        events[count].description[strcspn(events[count].description, "\n")] = 0;

        count++;
    }

    fclose(f);
    return count;
}
