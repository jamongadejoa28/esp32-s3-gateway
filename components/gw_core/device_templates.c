#include <string.h>
#include "gw_core/device_templates.h"

#define DEVICE_TEMPLATE(key, ...) static const gw_template_channel_t key##_channels[] = {
#define CHANNEL(id, key, ko, en, access, source, addr, scale, unit)                                          \
    {id, #key, ko, en, #access, #source, addr, scale, unit},
#define END_TEMPLATE(key)                                                                                    \
    }                                                                                                        \
    ;
#include "device_templates.def"
#undef DEVICE_TEMPLATE
#undef CHANNEL
#undef END_TEMPLATE

const gw_device_template_t gw_device_templates[] = {
#define DEVICE_TEMPLATE(key, id, name, vendor, category, description, baud, bits, parity, stop)              \
    {id,                                                                                                     \
     name,                                                                                                   \
     vendor,                                                                                                 \
     category,                                                                                               \
     description,                                                                                            \
     baud,                                                                                                   \
     bits,                                                                                                   \
     parity,                                                                                                 \
     stop,                                                                                                   \
     key##_channels,                                                                                         \
     sizeof(key##_channels) / sizeof(key##_channels[0])},
#define CHANNEL(...)
#define END_TEMPLATE(key)
#include "device_templates.def"
#undef DEVICE_TEMPLATE
#undef CHANNEL
#undef END_TEMPLATE
};
const size_t gw_device_template_count = sizeof(gw_device_templates) / sizeof(gw_device_templates[0]);

const gw_device_template_t *gw_device_template_find(const char *id) {
    if (!id)
        return NULL;
    for (size_t i = 0; i < gw_device_template_count; i++)
        if (strcmp(gw_device_templates[i].id, id) == 0)
            return &gw_device_templates[i];
    return NULL;
}
