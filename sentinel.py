# October
import curses
import time

def tail_file(filename):
    with open(filename, 'r') as file:
        file.seek(0, 2)  # Move to the end of the file
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

class WindowManager:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.windows = []
        self.layout = []
        curses.curs_set(0)
        curses.start_color()
        curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)

    def add_window(self, name, height_ratio, width_ratio, y_ratio, x_ratio, border_color=2, title=None):
        """
        Add a window with relative sizing and positioning.

        - height_ratio, width_ratio: Height and width as percentages (0-1) of the screen size.
        - y_ratio, x_ratio: Position of the top-left corner as percentages (0-1) of the screen size.
        """
        max_y, max_x = self.stdscr.getmaxyx()
        height = int(max_y * height_ratio)
        width = int(max_x * width_ratio)
        start_y = int(max_y * y_ratio)
        start_x = int(max_x * x_ratio)

        window = curses.newwin(height, width, start_y, start_x)
        window.attron(curses.color_pair(border_color))
        window.border()
        window.attroff(curses.color_pair(border_color))

        if title:
            window.addstr(0, 2, f' {title} ', curses.color_pair(border_color) | curses.A_BOLD)
        window.refresh()

        self.windows.append({'name': name, 'window': window})

    def get_window(self, name):
        """Retrieve a window by its name."""
        for win in self.windows:
            if win['name'] == name:
                return win['window']
        return None

    def clear_all(self):
        for win in self.windows:
            win['window'].clear()
            win['window'].refresh()

    def refresh_all(self):
        for win in self.windows:
            win['window'].refresh()

def main(stdscr):
    # Initialize WindowManager
    manager = WindowManager(stdscr)

    # Define layout by adding windows (name, height%, width%, y%, x%)
    manager.add_window("TitleWindow", height_ratio=0.1, width_ratio=1.0, y_ratio=0.0, x_ratio=0.0, border_color=3, title="MeshWatch 1.0")
    manager.add_window("DeviceInfo", height_ratio=0.3, width_ratio=0.5, y_ratio=0.1, x_ratio=0.0, border_color=2, title="Device Info")
    manager.add_window("Messages", height_ratio=0.3, width_ratio=0.5, y_ratio=0.1, x_ratio=0.5, border_color=1, title="Messages")
    manager.add_window("PacketData", height_ratio=0.5, width_ratio=1.0, y_ratio=0.4, x_ratio=0.0, border_color=2, title="Packet Data")

    log_file = "logfile.txt"  # Replace with your logfile path
    log_lines = tail_file(log_file)
    msg_window = manager.get_window("Messages")

    # Example loop to handle input and update windows
    while True:
        key = stdscr.getch()
        if key == ord('q'):
            break
        elif key == ord('c'):
            manager.clear_all()
        elif key == ord('r'):
            manager.refresh_all()
        elif key == ord('m') and msg_window:
            msg_window.addstr(1, 1, "New message received!", curses.color_pair(1))
            msg_window.refresh()
        
        # Display new log lines in the Messages window
        if msg_window:
            try:
                line = next(log_lines)
                msg_window.addstr(2, 1, line, curses.color_pair(1))
                msg_window.refresh()
            except StopIteration:
                pass

if __name__ == "__main__":
    curses.wrapper(main)