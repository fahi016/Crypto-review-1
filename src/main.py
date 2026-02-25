from tkinter import Tk

from .gui import ShamirGUI


def main():
    root = Tk()
    ShamirGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

