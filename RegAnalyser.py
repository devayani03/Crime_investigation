
from Interface import *
try:
    date = dt.datetime.now()
    logfile = str(date)[0:10]
    logging.basicConfig(filename='data/log/' + logfile + '.log', level=logging.DEBUG,
                        format='%(asctime)s - [%(levelname)s] --> %(message)s')
    logging.info('[RegAnalyser] RegAnalyser Started', extra={'investigator': 'RegAnalyser'})

    root = Tk()
    root.withdraw()
    root.title("RegAnalyser")
    root.iconbitmap("data/img/icon.ico")

    b = UserInterface(root)

    root.protocol('WM_DELETE_WINDOW', b.confirm_quit)
    b.center_window(root, 800, 450)
    root.tk.call('encoding', 'system', 'utf-8')
    root.mainloop()
    logging.info('[RegAnalyser] Ended', extra={'investigator': 'RegAnalyser'})

except Exception as e:
    print(str(e))
    logging.error('[RegAnalyser] An error occurred', exc_info=True, extra={'investigator': 'RegAnalyser'})


