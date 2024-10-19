import curses
import time
from textwindows import TextWindow

def main(stdscr):
    # Initialize curses
    curses.noecho()
    curses.cbreak()
    curses.curs_set(0)
    stdscr.nodelay(1)  # Non-blocking input
    stdscr.keypad(1)

    # Initialize colors
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
    curses.init_pair(6, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)

    # Calculate window sizes for two equal windows
    max_y, max_x = stdscr.getmaxyx()
    half_width = max_x // 2

    # Create two equally sized TextWindows
    window1 = TextWindow('Window1', rows=max_y - 1, columns=half_width, y1=0, x1=0, ShowBorder='Y', BorderColor=2, TitleColor=3)
    window2 = TextWindow('Window2', rows=max_y - 1, columns=half_width, y1=0, x1=half_width, ShowBorder='Y', BorderColor=2, TitleColor=4)

    # Refresh initial windows
    window1.refresh()
    window2.refresh()

    scrolling = True
    counter = 0

    while scrolling:
        # Check for key press
        key = stdscr.getch()
        if key != curses.ERR:
            scrolling = False
            break

        # Update both windows with scrolling text
        text = f"Scrolling line {counter}"
        window1.ScrollPrint(text, Color=3, TimeStamp=True)
        window2.ScrollPrint(text, Color=4, TimeStamp=True)
        window1.refresh()
        window2.refresh()

        # Increment counter and add delay
        counter += 1
        time.sleep(0.1)

curses.wrapper(main)
