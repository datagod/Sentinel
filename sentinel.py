# October

import curses
import textwindows
import time




def main(stdscr):
    # Call the helper function to initialize curses
    textwindows.initialize_curses(stdscr)


# Calculate window sizes for two equal windows
    max_y, max_x = stdscr.getmaxyx()
    window_width = max_x // 3

    # Create two equally sized TextWindows
    window1 = textwindows.TextWindow('Window1', rows=max_y - 1, columns=window_width, y1=0, x1=0, ShowBorder='Y', BorderColor=2, TitleColor=3)
    window2 = textwindows.TextWindow('Window2', rows=max_y - 1, columns=window_width, y1=0, x1=window_width, ShowBorder='Y', BorderColor=2, TitleColor=4)
    window3 = textwindows.TextWindow('Window3', rows=max_y - 1, columns=window_width, y1=0, x1=window_width *2, ShowBorder='Y', BorderColor=2, TitleColor=4)
    window3.ScrollPrint("test")
    

    # Refresh initial windows
    window1.refresh()
    window2.refresh()
    window3.refresh()
    time.sleep(4)
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
        window2.ScrollPrint(text, Color=4, TimeStamp=True)
        window1.refresh()
        window2.refresh()
        window2.refresh()

        # Increment counter and add delay
        counter += 1
        time.sleep(0.1)

curses.wrapper(main)

