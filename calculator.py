import tkinter as tk
from tkinter import ttk

class Calculator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Simple Calculator")
        # use a modern Windows-like theme if available
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('vista')
        except tk.TclError:
            pass

        self.expr = tk.StringVar()
        entry = ttk.Entry(self, textvariable=self.expr, justify='right', font=('Segoe UI', 20))
        entry.grid(row=0, column=0, columnspan=4, sticky='nsew')

        buttons = [
            ('7',1,0),('8',1,1),('9',1,2),('/',1,3),
            ('4',2,0),('5',2,1),('6',2,2),('*',2,3),
            ('1',3,0),('2',3,1),('3',3,2),('-',3,3),
            ('0',4,0),('.',4,1),('=',4,2),('+',4,3),
        ]
        for (text,row,col) in buttons:
            btn = ttk.Button(self, text=text, command=lambda t=text: self.on_click(t))
            btn.grid(row=row, column=col, sticky='nsew', padx=1, pady=1)

        for i in range(5):
            self.rowconfigure(i, weight=1)
            if i < 4:
                self.columnconfigure(i, weight=1)

        # bind keyboard input
        self.bind('<Key>', self.on_key)

    def on_click(self, char):
        if char == '=':
            try:
                result = str(eval(self.expr.get()))
                self.expr.set(result)
            except Exception:
                self.expr.set('Error')
        else:
            if self.expr.get() == 'Error':
                self.expr.set('')
            self.expr.set(self.expr.get() + char)

    def on_key(self, event):
        # allow digits, operators, and Enter
        char = event.char
        if char in '0123456789.+-*/':
            # regular input
            if self.expr.get() == 'Error':
                self.expr.set('')
            self.expr.set(self.expr.get() + char)
        elif event.keysym in ('Return', 'Equal'):
            # evaluate expression
            self.on_click('=')
        elif event.keysym == 'BackSpace':
            # delete last character
            self.expr.set(self.expr.get()[:-1])
        elif event.keysym == 'Escape':
            # clear
            self.expr.set('')

    def on_click(self, char):
        if char == '=':
            try:
                result = str(eval(self.expr.get()))
                self.expr.set(result)
            except Exception:
                self.expr.set('Error')
        else:
            if self.expr.get() == 'Error':
                self.expr.set('')
            self.expr.set(self.expr.get() + char)

if __name__ == "__main__":
    app = Calculator()
    app.mainloop()
