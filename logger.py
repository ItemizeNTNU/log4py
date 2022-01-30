from datetime import datetime as dt
import traceback
import sys


class Color():
    """ ANSI color codes """
    BLACK = '30m'
    RED = '31m'
    GREEN = '32m'
    YELLOW = '33m'
    BLUE = '34m'
    PURPLE = '35m'
    CYAN = '36m'
    WHITE = '37m'
    NORMAL = '\033[0;'
    BOLD = '\033[1;'
    FAINT = '\033[2;'
    ITALIC = '\033[3;'
    UNDERLINE = '\033[4;'
    BLINK = '\033[5;'
    NEGATIVE = '\033[7;'
    CROSSED = '\033[9;'
    END = '\033[0m'
    ESCAPE_PREFIX = '\033['
    CLEAR_LINE = '\033[2K'
    MOVE_TO_START_OF_LINE = '\033[0G'
    # cancel SGR codes if we don't write to a terminal
    if not __import__('sys').stdout.isatty():
        for _ in dir():
            if isinstance(_, str) and _[0] != '_':
                locals()[_] = ''
    else:
        # set Windows console in VT mode
        if __import__('platform').system() == 'Windows':
            kernel32 = __import__('ctypes').windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            del kernel32

    def test():
        color = ['black', 'red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'white']
        modes = ['normal', 'bold', 'faint', 'italic', 'underline', 'blink', 'negative', 'crossed']
        col1 = max(len(c) for c in color)
        col2 = max(len(m) for m in modes)
        width = col1 + col2 + 1
        for color in color:
            c = Color.__dict__[color.upper()]
            cname = color[0].upper() + color[1:].lower()
            for mode in modes:
                m = Color.__dict__[mode.upper()]
                mname = mode[0].upper() + mode[1:].lower()
                print(f'{m}{c}{(mname + " " + cname):<{width}}{Color.END}  ', prefix='', end='')
            print()


class Logger():
    def __init__(self, name):
        self.name = name

    def log_raw(self, level, level_color, text_color, *args, sep=' ', end='\n', **kwargs):
        # timestamp = dt.now().astimezone().strftime('[%F %T %Z] ')
        timestamp = dt.now().astimezone().strftime('[%T] ')
        prefix = Color.NORMAL + level_color + timestamp + Color.BOLD + level_color + f'[{level} {self.name}]: ' + Color.END
        if text_color:
            prefix += Color.NORMAL + text_color
            end = Color.END + end
        msg = sep.join(arg if type(arg) == str else repr(arg) for arg in args)
        if Color.ESCAPE_PREFIX in msg:
            end = Color.END + end
        msg = prefix + ('\n' + prefix).join(msg.split('\n'))
        msg = Color.CLEAR_LINE + Color.MOVE_TO_START_OF_LINE + msg
        print(msg, end=end, **kwargs)

    def log(self, level, *args, **kwargs):
        """
        Log a message at level `level`.

        Extends normal builtin `print`. Uses same arguments after `level`.
        """
        getattr(self, level)(*args, **kwargs)

    def success(self, *args, **kwargs):
        """
        Log success.

        Extends normal builtin `print`. Uses same arguments.
        """
        self.log_raw('SUCCESS', Color.GREEN, Color.GREEN, *args, **kwargs)

    def info(self, *args, **kwargs):
        """
        Log info.

        Extends normal builtin `print`. Uses same arguments.
        """
        self.log_raw('INFO', Color.BLUE, '', *args, **kwargs)

    def warn(self, *args, **kwargs):
        """
        Log warning.

        Extends normal builtin `print`. Uses same arguments.
        """
        self.log_raw('WARN', Color.YELLOW, Color.YELLOW, *args, **kwargs)

    def error_exception(self, msg, exception, **kwargs):
        """
        Log an exception as a warning.
        """
        self.error(f' {msg} '.center(80, '-'))
        self.error(traceback.format_exc())
        self.error('-'*80)

    def error(self, *args, **kwargs):
        """
        Log errors in red.

        Extends normal builtin `print`. Uses same arguments.
        """
        self.log_raw('ERROR', Color.RED, Color.RED, file=sys.stderr, *args, **kwargs)
