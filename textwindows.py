#------------------------------------------------------------------------------
# Author: William McEvoy AND ChatGPT                                         --
# Created: Oct 12 2024                                                       --
#                                                                            --
# Purpose:  TextWindow and TextPad classes for creating and managing text    --
#           windows and pads in a curses-based terminal interface. This file --
#           can be used as a standalone module to integrate with other       --
#           programs requiring a simple curses-based user interface.         --
#                                                                            --
# Usage:                                                                     --
#   To use the TextWindow or TextPad class in another Python program,        --
#   import this module and create instances of the classes by providing      --
#   appropriate parameters for the window or pad dimensions, coordinates,    --
#   and styles.                                                              --
#                                                                            --
# Example:                                                                   --
#   from textwindow import TextWindow, TextPad                               --
#                                                                            --
#   window1 = TextWindow('Window1', 10, 40, 0, 0, 10, 40, 'Y', 2, 2)         --
#   window1.ScrollPrint("Hello, World!", Color=3, TimeStamp=True)            --
#                                                                            --
#   pad1 = TextPad('Pad1', 100, 40, 1, 1, 10, 40, 'N', 2)                    --
#   pad1.PadPrint("This is a long text to be printed in a pad.", Color=4)    --
#                                                                            --
#------------------------------------------------------------------------------
#
# Imported Modules:                                                          --
#   - curses: Provides functions to create text-based user interfaces.       --
#   - traceback: Used for generating and formatting stack trace information  --
#                when exceptions occur.                                      --
#   - datetime: Used for creating timestamps for messages displayed in the   --
#               TextWindow and TextPad.                                      --
#   - time: Provides time-related functions used in error handling.          --
#   - sys: Provides access to system-specific parameters and functions,      --
#          used in error handling to exit the program gracefully.            --
#   - inspect: Used to get information about the current stack frame to      --
#              determine the calling function in the error handler.          --
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Queue Processing in TextWindow Module                                      --
#                                                                            --
# This module includes a global queue processing mechanism designed to       --
# handle asynchronous message delivery to TextWindow instances. The          --
# queue allows messages to be enqueued along with metadata (e.g., target     --
# window name, text color, timestamp) and processed independently, enabling  --
# smooth, non-blocking updates to text-based windows in a curses interface.  --
#                                                                            --
# How It Works:                                                              --
# 1. **Global Message Queue**:                                               --
#    - A thread-safe queue (`message_queue`) is used to store messages.       --
#    - Each message includes the target window name and associated details.  --
#                                                                            --
# 2. **Message Enqueuing**:                                                  --
#    - The `EnqueuePrint` method in `TextWindow` allows messages to be added --
#      to the queue, specifying the text to display, color, timestamp, and   --
#      formatting options.                                                   --
#                                                                            --
# 3. **Queue Processor**:                                                    --
#    - A dedicated thread (`queue_processor_thread`) runs continuously to    --
#      process messages from the queue.                                      --
#    - For each message, the processor identifies the target window (by name)--
#      and invokes the `ScrollPrint` method to display the message.          --
#    - If the target window does not exist, an error is logged but the       --
#      processor continues without interruption.                             --
#                                                                            --
# 4. **Benefits**:                                                           --
#    - Decouples message generation from rendering, allowing multiple        --
#      threads or systems to enqueue messages without blocking.              --
#    - Enables centralized control of message rendering, simplifying logging --
#      and debugging of text output.                                         --
#                                                                            --
# 5. **Thread Safety**:                                                      --
#    - The `queue.Queue` ensures safe concurrent access to the message queue,--
#      avoiding race conditions when multiple threads enqueue messages.      --
#                                                                            --
# Usage:                                                                     --
# - Create TextWindow instances and use their `EnqueuePrint` method to send  --
#   messages to the queue. The queue processor will handle rendering.         --
#                                                                            --
# Example:                                                                   --
#   window1 = TextWindow('Window1', 'Title1', 10, 40, 0, 0, 'Y', 2, 3)       --
#   window1.EnqueuePrint("Hello, World!", Color=4, TimeStamp=True)           --
#                                                                            --
# Notes:                                                                     --
# - The queue processor thread starts automatically when the module is       --
#   imported, ensuring seamless message handling.                            --
# - For graceful shutdown, you can signal the processor to stop by enqueuing --
#   a special sentinel value (e.g., `None`).                                 --
#                                                                            --
#------------------------------------------------------------------------------ 


import curses
import traceback
from datetime import datetime
import time
import sys
import inspect
import logging
import threading


class BaseTextInterface:
    def __init__(self, name):
        self.name = name
        # Setup logging once
        logging.basicConfig(filename=f'{self.name}.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')




    def ErrorHandler(self, ErrorMessage, TraceMessage, AdditionalInfo):
        # Log the error using the logging module
        logging.debug(f"ERROR: {ErrorMessage}")
        logging.debug(f"TRACE: {TraceMessage}")
        if AdditionalInfo:
            logging.debug(f"Additional Info: {AdditionalInfo}")

        # Also print to console if necessary
        #print("ERROR - An error occurred in TextWindow or TextPad class.")
        #print(ErrorMessage)
        #print("TRACE")
        #print(TraceMessage)
        #if AdditionalInfo:
        #    print("Additional info:", AdditionalInfo)


        # Optional delay to give time for users to read the error (if used interactively)
        time.sleep(5)



    def log_debug(self, message):
        logging.debug(message)



class TextWindow(BaseTextInterface):
    def __init__(self, name, title, rows, columns, y1, x1, ShowBorder, BorderColor, TitleColor):
        max_y, max_x = curses.LINES - 1, curses.COLS - 1
        self.rows = min(rows, max_y - y1)
        self.columns = min(columns, max_x - x1)

        #Setup variables
        self.name  = name
        self.title = title
        self.y1    = y1
        self.x1    = x1
        self.y2    = self.y1 + rows
        self.x2    = self.x1 + rows
        self.ShowBorder = ShowBorder
        self.BorderColor = BorderColor  # pre-defined text colors 1-7
        self.TitleColor = TitleColor

        try:
            self.window = curses.newwin(self.rows, self.columns, self.y1, self.x1)
        except curses.error:
            raise ValueError("Failed to create a new window. Check if terminal size is sufficient.")

        #Set up logging
        logging.basicConfig(filename=f'{self.name}.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

        #Basic bounds check
        if self.rows <= 0 or self.columns <= 0:
            raise ValueError("Window size exceeds terminal size. Please expand your terminal.")
        self.CurrentRow = 1
        self.StartColumn = 1
        self.DisplayRows = self.rows  # We will modify this later, based on if we show borders or not
        self.DisplayColumns = self.columns  # We will modify this later, based on if we show borders or not
        self.PreviousLineText = ""
        self.PreviousLineRow = 0
        self.PreviousLineColor = 2

        if self.ShowBorder == 'Y':
            self.CurrentRow = 1
            self.StartColumn = 1
            self.DisplayRows = self.rows - 2
            self.DisplayColumns = self.columns - 2
            self.window.attron(curses.color_pair(BorderColor))
            self.window.border()
            self.window.attroff(curses.color_pair(BorderColor))
        else:
            self.CurrentRow = 0
            self.StartColumn = 0



    def QueuePrint(self, message, Color=2, TimeStamp=False, BoldLine=True):
        """
        Add a message to the global queue for this window.
        """
        message_queue.put({
            "window_name": self.name,
            "message": message,
            "Color": Color,
            "TimeStamp": TimeStamp,
            "BoldLine": BoldLine
        })





    def ScrollPrint(self, PrintLine, Color=2, TimeStamp=False, BoldLine=True):
        # Debugging: Log the input line details
        #logging.debug(f"ScrollPrint called with: PrintLine='{PrintLine}', Color={Color}, TimeStamp={TimeStamp}, BoldLine={BoldLine}")
        
        # Convert PrintLine to string, remove nulls, special characters, and newlines
        PrintLine = str(PrintLine).replace('\0', '')  # Remove any embedded null characters
        PrintLine = PrintLine.replace('\n', ' ')  # Remove newline characters
        PrintLine = PrintLine.encode('utf-8', 'replace').decode('utf-8')
        current_time = datetime.now().strftime("%H:%M:%S")

        if TimeStamp:
            PrintLine = current_time + ": {}".format(PrintLine)

        PrintLine = PrintLine.expandtabs(4)
        PrintableString = PrintLine[0:self.DisplayColumns]
        RemainingString = PrintLine[self.DisplayColumns:]

        try:
            while len(PrintableString) > 0:
                PrintableString = PrintableString.ljust(self.DisplayColumns, ' ')


                # Make sure we're within bounds, loop around
                if self.CurrentRow >= self.DisplayRows or self.CurrentRow < 0:
                    #logging.debug("WARNING: CurrentRow is out of bounds, adjusting row number.\n")
                    #logging.debug(f"CurrentRow: {self.CurrentRow}, DisplayRows: {self.DisplayRows}, StartColumn: {self.StartColumn}, PrintableString: '{PrintableString}'\n")
                    self.CurrentRow = 1  # Reset or handle accordingly

                self.window.attron(curses.color_pair(self.PreviousLineColor))
                self.window.addstr(self.PreviousLineRow, self.StartColumn, self.PreviousLineText)
                self.window.attroff(curses.color_pair(self.PreviousLineColor))

                if BoldLine:
                    self.window.attron(curses.color_pair(Color))
                    self.window.addstr(self.CurrentRow, self.StartColumn, PrintableString, curses.A_BOLD)
                    self.window.attroff(curses.color_pair(Color))
                else:
                    self.window.attron(curses.color_pair(Color))
                    self.window.addstr(self.CurrentRow, self.StartColumn, PrintableString)
                    self.window.attroff(curses.color_pair(Color))

                self.PreviousLineText = PrintableString
                self.PreviousLineColor = Color
                self.PreviousLineRow = self.CurrentRow
                self.CurrentRow = self.CurrentRow + 1

                PrintableString = RemainingString[0:self.DisplayColumns]
                RemainingString = RemainingString[self.DisplayColumns:]

            if self.CurrentRow > (self.DisplayRows):
                if self.ShowBorder == 'Y':
                    self.CurrentRow = 1
                else:
                    self.CurrentRow = 0

            # Draw border and refresh
            #if self.ShowBorder == 'Y':
            #    self.window.border()
            self.window.refresh()

        except curses.error as e:
          # Log the curses-specific error
          logging.debug(f"ERROR: Curses error occurred: {e}")

        except Exception as ErrorMessage:
          TraceMessage  = traceback.format_exc()
          AdditionalInfo = f"PrintLine: {PrintLine}, CurrentRow: {self.CurrentRow}, DisplayRows: {self.DisplayRows}"

          # Call ErrorHandler to do the necessary handling and logging in one place
          self.ErrorHandler(ErrorMessage, TraceMessage, AdditionalInfo)                           



    def DisplayTitle(self, Title='', x=2, filler='─'):
        # Display the object's title, or a custom one 
        # Use self.title if available, otherwise fall back to Title
        DisplayTitle = self.title if self.title else Title
        DisplayTitle = Title if Title != '' else self.title 

        # Replace spaces in the title with the filler character
        DisplayTitle = DisplayTitle.replace(' ', filler)

        # Ensure that the title length fits within the window width minus a buffer
        max_title_length = max(self.DisplayColumns - 3, 0)
        DisplayTitle = DisplayTitle[:max_title_length]

        try:
            # Only display the title if there are enough rows in the window
            if self.rows > 2:
                self.window.attron(curses.color_pair(self.TitleColor))
                self.window.addstr(0, x, DisplayTitle)
                self.window.attroff(curses.color_pair(self.TitleColor))
            else:
                print("ERROR - You cannot display title on a window smaller than 3 rows")

        except Exception as ErrorMessage:
            # Capture detailed error information for debugging
            TraceMessage = traceback.format_exc()
            AdditionalInfo = f"Title: {DisplayTitle}"
            self.ErrorHandler(ErrorMessage, TraceMessage, AdditionalInfo)




    def Clear(self):
        self.window.erase()
        self.window.attron(curses.color_pair(self.BorderColor))
        self.window.border()
        self.window.attroff(curses.color_pair(self.BorderColor))
        self.DisplayTitle()
        if self.ShowBorder == 'Y':
            self.CurrentRow = 1
            self.StartColumn = 1
        else:
            self.CurrentRow = 0
            self.StartColumn = 0

    def refresh(self):
        #self.window.touchwin()  
        self.window.refresh()


    def UpdateLine(self, row, column, text, Color=2, Bold=False):
        """
        Updates the same line of text in the window.

        Parameters:
        - row, column: Coordinates for where to place the text.
        - text: The text to display.
        - Color: Color pair to use (default is 2).
        - Bold: Whether to display the text in bold (default is False).
        """
        try:
            # Truncate the text if it's longer than the display columns
            text = text[:self.DisplayColumns - column]

            # Set the color and optionally bold
            if Bold:
                self.window.attron(curses.color_pair(Color) | curses.A_BOLD)
            else:
                self.window.attron(curses.color_pair(Color))

            # Write the text at the specified row and column
            self.window.addstr(row, column, text)

            # Turn off the attributes
            if Bold:
                self.window.attroff(curses.color_pair(Color) | curses.A_BOLD)
            else:
                self.window.attroff(curses.color_pair(Color))

            # Refresh the window to update display
            self.window.refresh()

        except curses.error as e:
            # Handle any curses-specific errors
            logging.debug(f"ERROR: Curses error occurred in UpdateLine: {e}")

        except Exception as ErrorMessage:
            # Generic error handler
            TraceMessage = traceback.format_exc()
            AdditionalInfo = f"Updating Line: row={row}, column={column}, text={text}"
            self.ErrorHandler(ErrorMessage, TraceMessage, AdditionalInfo)





    @staticmethod
    def ProcessQueue():
        """
        Continuously process the global message queue and call ScrollPrint for the appropriate window.
        """
        while True:
            try:
                # Get the next message from the queue
                item = message_queue.get()
                if item is None:
                    break  # Exit loop if None is received

                # Extract details
                window_name = item["window_name"]
                message = item["message"]
                Color = item.get("Color", 2)
                TimeStamp = item.get("TimeStamp", False)
                BoldLine = item.get("BoldLine", True)

                # Find the window and call ScrollPrint
                window = TextWindow.windows.get(window_name)
                if window:
                    window.ScrollPrint(message, Color=Color, TimeStamp=TimeStamp, BoldLine=BoldLine)
                else:
                    logging.debug(f"Window '{window_name}' not found for message: {message}")

            except Exception as e:
                logging.debug(f"Error processing message queue: {e}")




class HeaderWindow(TextWindow):
    """
    HeaderWindow is a specialized extension of the TextWindow class that provides functionality 
    for managing a header display area with fixed, updateable lines of text. It allows specific 
    rows in the header to be defined with content that can be dynamically updated or refreshed as needed.

    Attributes:
        fixed_lines (dict): Stores fixed lines as a dictionary where keys are row numbers and values are the text.
        current_lines (dict): Tracks the current content of the fixed lines to avoid unnecessary updates.

    Args:
        name (str):    The name of the window.
        title (str):   The title displayed on the header.
        rows (int):    The number of rows in the window.
        columns (int): The number of columns (width) of the window.
        y1 (int):      The starting y-coordinate of the window.
        x1 (int):      The starting x-coordinate of the window.
        ShowBorder (bool): Whether to show a border around the window.
        BorderColor (str): The color used for the border.
        TitleColor (str):  The color used for the title and fixed lines.
        fixed_lines (list or dict): A list of tuples [(row, text)] or a dictionary {row: text} 
                                    representing the fixed lines to initialize in the header.

    Methods:
        _initialize_fixed_lines():
            Sets the initial content for all fixed lines at the header.
        
        update_fixed_line(row, text, Color=None):
            Updates a specific fixed line only if the new content is different from the current content.
        
        set_fixed_lines(updates, Color=None):
            Updates multiple fixed lines in one call, only changing lines whose content differs from the current content.
        
        refresh_header():
            Re-draws all fixed lines if their content has changed.

    Example:
        header = HeaderWindow(
            name="MainHeader",
            title="My Application",
            rows=5, columns=50, y1=0, x1=0,
            ShowBorder=True, BorderColor="blue", TitleColor="green",
            fixed_lines=[(0, "Welcome to My Application"), (2, "User: John Doe")]
        )
        
        # Initialize header with fixed lines
        header.refresh_header()

        # Update a specific line - only changes if the new content is different
        header.update_fixed_line(2, "User: Jane Smith", Color="yellow")

        # Update multiple lines at once
        header.set_fixed_lines({0: "Welcome to the Updated Application", 2: "User: Alice"}, Color="red")

        # Refresh all lines if necessary
        header.refresh_header()

    Raises:
        ValueError: If the fixed_lines argument is neither a list of tuples nor a dictionary.
        ValueError: If an attempt is made to access a row outside the bounds of the HeaderWindow.
        ValueError: If an attempt is made to update a row that is not part of the fixed header lines.
    """


    def __init__(self, name, title, rows, columns, y1, x1, ShowBorder, BorderColor, TitleColor, fixed_lines):
        """
        Initialize the HeaderWindow.

        Args:
            name, title, rows, columns, y1, x1, ShowBorder, BorderColor, TitleColor:
                Parameters to pass to the TextWindow initializer.
            fixed_lines (list or dict): A list of tuples [(row, text)] or a dictionary {row: text}.
        """
        super().__init__(name, title, rows, columns, y1, x1, ShowBorder, BorderColor, TitleColor)
        
        # Convert to dictionary if fixed_lines is a list
        if isinstance(fixed_lines, list):
            self.fixed_lines = dict(fixed_lines)  # Convert list of tuples to dict
        elif isinstance(fixed_lines, dict):
            self.fixed_lines = fixed_lines
        else:
            raise ValueError("fixed_lines must be a list of (row, text) tuples or a dictionary {row: text}.")

        # Initialize current_lines to track the current state of each line
        self.current_lines = {}
        
        self._initialize_fixed_lines()

    def _initialize_fixed_lines(self):
        """Sets the initial content for all fixed lines."""
        for row, text in self.fixed_lines.items():
            if 0 <= row < self.DisplayRows:  # Ensure rows are within bounds
                self.current_lines[row] = text  # Track the initial state
                self.UpdateLine(row, 1, text, Color=self.TitleColor, Bold=True)
            else:
                raise ValueError(f"Row {row} is out of bounds for the HeaderWindow.")

    def update_fixed_line(self, row, text, Color=None):
        """
        Update a specific fixed line only if it has changed.

        Args:
            row (int): The row number to update.
            text (str): The new text for the fixed line.
            Color (str): Optional; color to use for the line. Defaults to TitleColor if None.
        """
        if row not in self.fixed_lines:
            raise ValueError(f"Row {row} is not defined as a fixed header line.")

        # Only update if the text is different
        if self.current_lines.get(row) != text:
            self.current_lines[row] = text  # Update the current state
            self.UpdateLine(row, 1, text, Color=Color if Color else self.TitleColor, Bold=True)

    def set_fixed_lines(self, updates, Color=None):
        """
        Update multiple fixed lines at once, only if the content has changed.

        Args:
            updates (dict): A dictionary of updates {row: new_text}.
        """
        for row, text in updates.items():
            self.update_fixed_line(row, text, Color)

    def refresh_header(self):
        """Re-draw all fixed lines if they have changed."""
        for row, text in self.fixed_lines.items():
            if self.current_lines.get(row) != text:
                self.update_fixed_line(row, text)

        self.refresh()


class TextPad(object):
    def __init__(self, name, rows, columns, y1, x1, y2, x2, ShowBorder, BorderColor):
        max_y, max_x = curses.LINES - 1, curses.COLS - 1
        self.rows = min(rows, max_y - y1)
        self.columns = min(columns, max_x - x1)

        if self.rows <= 0 or self.columns <= 0:
            raise ValueError("Pad size exceeds terminal size. Please expand your terminal.")
        
        self.name = name
        self.ypos = y1  # Position on the screen
        self.xpos = x1
        self.height = self.rows
        self.width = self.columns
        self.ShowBorder = ShowBorder
        self.BorderColor = BorderColor  # pre-defined text colors 1-7
        try:
            self.pad = curses.newpad(self.rows, self.columns)
        except curses.error:
            raise ValueError("Failed to create a new pad. Check if terminal size is sufficient.")
        self.PreviousLineColor = 2

    def PadPrint(self, PrintLine, Color=2, TimeStamp=False):
        # Print to the pad
        try:
            self.pad.idlok(1)
            self.pad.scrollok(1)

            current_time = datetime.now().strftime("%H:%M:%S")
            if TimeStamp:
                PrintLine = current_time + ": " + PrintLine

            # Expand tabs to X spaces
            PrintLine = PrintLine.expandtabs(4)
            # Pad the string with space then truncate
            PrintLine = PrintLine.ljust(self.columns, ' ')
            PrintLine = PrintLine[:self.columns - 1]  # Truncate to fit

            self.pad.attron(curses.color_pair(Color))
            self.pad.addstr(PrintLine + '\n')
            self.pad.attroff(curses.color_pair(Color))

            # Do not refresh here
            # self.refresh()

        except Exception as ErrorMessage:
            time.sleep(2)
            TraceMessage = traceback.format_exc()
            AdditionalInfo = "PrintLine: " + PrintLine
            self.ErrorHandler(ErrorMessage, TraceMessage, AdditionalInfo)

    def refresh(self):
        # Calculate the refresh area
        max_y, max_x = curses.LINES - 1, curses.COLS - 1
        pad_max_y, pad_max_x = self.ypos + self.height - 1, self.xpos + self.width - 1

        refresh_y1 = min(self.ypos, max_y)
        refresh_x1 = min(self.xpos, max_x)
        refresh_y2 = min(pad_max_y, max_y)
        refresh_x2 = min(pad_max_x, max_x)

        self.pad.refresh(
            0, 0,
            refresh_y1, refresh_x1,
            refresh_y2, refresh_x2
        )

    def Clear(self):
        try:
            self.pad.erase()
            self.refresh()
        except Exception as ErrorMessage:
            TraceMessage = traceback.format_exc()
            AdditionalInfo = "erasing textpad"
            self.ErrorHandler(ErrorMessage, TraceMessage, AdditionalInfo)

    def ErrorHandler(self, ErrorMessage, TraceMessage, AdditionalInfo):
        print("ERROR - An error occurred in TextPad class.")
        print(ErrorMessage)
        print("TRACE")
        print(TraceMessage)
        if AdditionalInfo:
            print("Additional info:", AdditionalInfo)


# Global variable to hold the typed text
typed_text = ""

def PollKeyboard(stdscr):
    # Get key press (polling)
    try:
        c = stdscr.getch()
        if c != curses.ERR:
            return c  # Return the pressed key
        else:
            return None
    except Exception as ErrorMessage:
        traceback.print_exc()
        return None

def ProcessKeypress(c, pad):
    global typed_text

    try:
        if c == 27:  # Escape key to exit
            return "EXIT"

        elif c == 10:  # Enter key, print typed text to pad
            pad.PadPrint(typed_text, Color=3, TimeStamp=True)
            typed_text = ""

        elif c == 8 or c == 127:  # Backspace key
            typed_text = typed_text[:-1]

        elif 0 <= c <= 255:
            typed_text = chr(c)

        # Display the currently typed text in the pad
        pad.PadPrint(f"{typed_text}", Color=6)
        pad.refresh()

        return None

    except Exception as ErrorMessage:
        traceback.print_exc()
        return None



def initialize_curses(stdscr):
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




def get_screen_dimensions(stdscr):
    # Get the screen dimensions
    height, width = stdscr.getmaxyx()
    return height, width

curses.wrapper(lambda stdscr: print(get_screen_dimensions(stdscr)))


# Start the queue processing thread automatically
queue_processor_thread = threading.Thread(target=TextWindow.ProcessQueue, daemon=True)
queue_processor_thread.start()
