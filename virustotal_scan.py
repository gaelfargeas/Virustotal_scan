from virustotal_python import Virustotal

from tkinter import (
    Tk,
    Label,
    Button,
    Menu,
    Canvas,
    PanedWindow,
    Frame,
    Scrollbar,
    Listbox,
    Checkbutton,
)

from tkinter.filedialog import (
    askdirectory,
    askopenfilename,
    askopenfilenames,
    asksaveasfilename,
)

from tkinter.messagebox import showinfo

from tkinter.ttk import Combobox

from tkinter import (
    LEFT,
    RIGHT,
    TOP,
    BOTTOM,
    HORIZONTAL,
    VERTICAL,
    CENTER,
    X,
    Y,
    BOTH,
    DISABLED,
    NORMAL,
    Toplevel,
)

from os.path import basename, isfile, getsize

from os import listdir

from time import sleep

import json, threading, virustotal_exception, datetime, pickle

from virustotal_text import about_text

from hashlib import sha256

from API_key import API_key

DEBUG = False

vtotal = Virustotal(API_key)

# care file to scan can be add multiple time

# TODO : upgrade le thread : dans stop_scan : la il att que le scan soit fini avant de tous couper: du coup ça peut prendre du temps
# TODO : la doc sphinx


class virustotal_scan(threading.Thread):
    """
    A class used to scan file(s) using Virustotal Public API

    Attributes
    ----------
    init_end            : bool
        Flag use to enable resize event
    Waiting_file_list   : list, str
        List of Waiting files address (files to scan)
    OK_file_list        : list, str
        List of OK files address (file scanned)
    NOK_file_list       : list, str
        List of NOK files address (file scanned)
    main_windows             : Tk
        Tkinter main window
    menubar : 
    ...
    ok_list             : Listbox
        listbox which contain ok files address
    Nok_list            : Listbox
        listbox which contain Nok files address
    Waiting_list        : Listbox
        listbox which contain waiting to be scanned files address
    

    Methods
    -------
    show_help()
        Show Help in a new windows
    resize_windows(event)
        Dynamically resize Frame, panedwindows width depend on main windows width
    update_waiting_list(files_list_name)
        Clear and update waiting_list Listbox
    update_ok_list(files_list_name)
        Clear and update ok_list Listbox
    update_Nok_list(files_list_name)
        Clear and update Nok_list Listbox
    """

    def __init__(self, *args, **kwargs):
        """ 
        Init class using tkinter to make an graphic interface        
        """
        super(virustotal_scan, self).__init__(*args, **kwargs)

        # ====================== variables ======================
        self.THREAD_IS_ACTIVE = True
        self.thread_down = False
        self.scan_stopped = False
        self.call_start_scan = False
        self.force_scan = False
        self.error_log_list = list("")
        self.init_end = False
        self.Waiting_file_list = list("")
        self.OK_file_list = list("")
        self.NOK_file_list = list("")
        self.Nok_file_list_scan_result_dict = dict()
        self.main_widows = Tk()

        # ====================== init main windows ======================

        self.main_widows.protocol("WM_DELETE_WINDOW", self.close_app)
        self.main_widows.title("VIRUSTOTAL SCAN")
        self.main_widows.minsize(600, 480)
        self.main_widows.geometry("600x500")
        self.main_widows.iconbitmap(".\\img\\vt_logo.ico")

        # ====================== menu top bar ======================

        self.menubar = Menu(self.main_widows)

        self.menu_help = Menu(self.menubar, tearoff=0)
        self.menu_help.add_command(label="A propos", command=self.show_help)
        self.menu_help.add_command(label="ERROR LOGS", command=self.show_error_log)

        self.menubar.add_cascade(label="Aide", menu=self.menu_help)

        self.menu_save = Menu(self.menubar, tearoff=0)
        self.menu_save.add_command(label="Import", command=self.import_waiting_list)
        self.menu_save.add_command(label="Export", command=self.export_waiting_list)

        self.menubar.add_cascade(label="Save/Load", menu=self.menu_save)

        self.menubar.add_command(label="Quitter", command=self.close_app)

        self.menubar.add_command(label="Clear", command=self.clear_list)

        self.menubar.add_command(label="Nok result", command=self.show_nok_result)

        self.main_widows.config(menu=self.menubar)

        # ====================== top texte ======================

        self.label = Label(self.main_widows, text="Virus Total Scan")
        self.label.pack()

        # ====================== first panelwindow ======================

        self.first_panelwindow = PanedWindow(
            self.main_widows, orient=HORIZONTAL, width=self.main_widows.winfo_width()
        )

        self.first_panelwindow.bind("<Configure>", self.resize_windows)

        self.first_panelwindow.pack(fill=X)

        # ====================== OK list ======================

        self.ok_list_panedwindow = PanedWindow(
            self.first_panelwindow, height=200, width=100, background="ivory"
        )
        self.ok_list_panedwindow.grid_propagate(False)
        self.ok_list_panedwindow.propagate(False)
        self.ok_list_panedwindow.pack(side=LEFT, padx=5, pady=5)

        Label(self.ok_list_panedwindow, text="File(s) clean", background="ivory").pack(
            fill=X
        )

        self.ok_list_frame = Frame(self.ok_list_panedwindow, background="ivory")
        self.ok_list_frame.pack(fill=X, padx=5, pady=5)

        ok_list_scrollbar_X = Scrollbar(self.ok_list_frame, orient=HORIZONTAL)
        ok_list_scrollbar_X.pack(side=TOP, fill=X)

        ok_list_scrollbar_Y = Scrollbar(self.ok_list_frame, orient=VERTICAL)
        ok_list_scrollbar_Y.pack(side=RIGHT, fill=Y)

        self.ok_list = Listbox(
            self.ok_list_frame,
            yscrollcommand=ok_list_scrollbar_Y.set,
            xscrollcommand=ok_list_scrollbar_X.set,
        )

        self.ok_list.pack(side=LEFT)
        ok_list_scrollbar_Y.config(command=self.ok_list.yview)
        ok_list_scrollbar_X.config(command=self.ok_list.xview)

        # ====================== waiting list ======================

        self.Waiting_list_panedwindow = PanedWindow(
            self.first_panelwindow, height=200, width=100, background="ivory"
        )
        self.Waiting_list_panedwindow.grid_propagate(False)
        self.Waiting_list_panedwindow.propagate(False)
        self.Waiting_list_panedwindow.pack(side=LEFT, padx=5, pady=5)

        Label(
            self.Waiting_list_panedwindow, text="File(s) List", background="ivory"
        ).pack(fill=X)

        self.Waiting_list_frame = Frame(
            self.Waiting_list_panedwindow, background="ivory"
        )
        self.Waiting_list_frame.pack(fill=X, padx=5, pady=5)

        Waiting_list_scrollbar_X = Scrollbar(self.Waiting_list_frame, orient=HORIZONTAL)
        Waiting_list_scrollbar_X.pack(side=TOP, fill=X)

        Waiting_list_scrollbar_Y = Scrollbar(self.Waiting_list_frame, orient=VERTICAL)
        Waiting_list_scrollbar_Y.pack(side=RIGHT, fill=Y)

        self.Waiting_list = Listbox(
            self.Waiting_list_frame,
            yscrollcommand=Waiting_list_scrollbar_Y.set,
            xscrollcommand=Waiting_list_scrollbar_X.set,
        )

        self.Waiting_list.pack(side=LEFT)
        Waiting_list_scrollbar_Y.config(command=self.Waiting_list.yview)
        Waiting_list_scrollbar_X.config(command=self.Waiting_list.xview)

        # ====================== second panelwindow ======================

        self.second_panelwindow = PanedWindow(
            self.main_widows, orient=HORIZONTAL, width=self.main_widows.winfo_width()
        )

        self.second_panelwindow.pack(fill=X)

        # ====================== NOK list ======================

        self.Nok_list_panedwindow = PanedWindow(
            self.second_panelwindow, height=150, width=100, background="ivory"
        )
        self.Nok_list_panedwindow.grid_propagate(False)
        self.Nok_list_panedwindow.propagate(False)
        self.Nok_list_panedwindow.pack(side=LEFT, padx=5, pady=5)

        Label(
            self.Nok_list_panedwindow, text="File(s) unclean", background="ivory"
        ).pack(fill=X)

        self.Nok_list_frame = Frame(self.Nok_list_panedwindow, background="ivory")
        self.Nok_list_frame.pack(fill=X, padx=5, pady=5)

        Nok_list_scrollbar_X = Scrollbar(self.Nok_list_frame, orient=HORIZONTAL)
        Nok_list_scrollbar_X.pack(side=TOP, fill=X)

        Nok_list_scrollbar_Y = Scrollbar(self.Nok_list_frame, orient=VERTICAL)
        Nok_list_scrollbar_Y.pack(side=RIGHT, fill=Y)

        self.Nok_list = Listbox(
            self.Nok_list_frame,
            yscrollcommand=Nok_list_scrollbar_Y.set,
            xscrollcommand=Nok_list_scrollbar_X.set,
        )

        self.Nok_list.pack(side=LEFT)
        Nok_list_scrollbar_Y.config(command=self.Nok_list.yview)
        Nok_list_scrollbar_X.config(command=self.Nok_list.xview)

        # ====================== button ======================

        self.button_panedwindow = PanedWindow(
            self.second_panelwindow, height=100, width=100
        )
        self.button_panedwindow.grid_propagate(False)
        self.button_panedwindow.propagate(False)
        self.button_panedwindow.pack(side=LEFT, padx=5, pady=5)

        self.bouton_scan_file = Button(
            self.button_panedwindow, text="Select files", command=self.select_scan_file
        )
        self.bouton_scan_file.grid(row=0, column=0, padx=5, pady=5)

        self.bouton_scan_dir = Button(
            self.button_panedwindow,
            text="Select directory",
            command=self.select_scan_dir,
        )
        self.bouton_scan_dir.grid(row=0, column=1, padx=5, pady=5)

        self.bouton_delete = Button(
            self.button_panedwindow, text="Delete", command=self.remove_to_waiting_list
        )
        self.bouton_delete.grid(row=0, column=2, padx=5, pady=5)

        self.bouton_start_scan = Button(
            self.button_panedwindow, text="Start scan", command=self.start_scan
        )
        self.bouton_start_scan.grid(row=1, column=0, padx=5, pady=5)

        self.bouton_stop_scan = Button(
            self.button_panedwindow,
            text="Stop scan",
            command=self.stop_scan,
            state=DISABLED,
        )
        self.bouton_stop_scan.grid(row=1, column=1, padx=5, pady=5)

        self.bouton_check_force_scan = Checkbutton(
            self.button_panedwindow, text="Force Scan", command=self.set_force_scan
        )
        self.bouton_check_force_scan.grid(row=1, column=2, padx=5, pady=5)

        self.curent_scan_file_label = Label(self.button_panedwindow, text="")
        self.curent_scan_file_label.grid(row=3, column=0, columnspan=4, padx=5, pady=5)

        # ====================== init end ======================

        self.init_end = True

        # start thread
        self.start()

        self.main_widows.mainloop()

    def run(self):
        """
        Thread run fonction
        """
        while self.THREAD_IS_ACTIVE:

            sleep(0.5)

            if self.call_start_scan:
                try:
                    self.bouton_scan_file.config(state=DISABLED)
                    self.bouton_scan_dir.config(state=DISABLED)
                    self.bouton_start_scan.config(state=DISABLED)
                    self.bouton_stop_scan.config(state=NORMAL)

                    # while not self.scan_stopped:
                    #     if len(self.Waiting_file_list) != 0:
                    self.scan_file()

                    self.bouton_stop_scan.config(state=DISABLED)
                    self.bouton_start_scan.config(state=NORMAL)
                    self.bouton_scan_file.config(state=NORMAL)
                    self.bouton_scan_dir.config(state=NORMAL)

                except Exception:
                    pass

        self.thread_down = True

    def show_error_log(self):
        """
        Show error log in a new window
        """

        error_log_windows = Toplevel(self.main_widows)

        error_log_windows.title("VIRUSTOTAL SCAN : ERROR log")
        error_log_windows.minsize(600, 480)
        error_log_windows.geometry("600x500")
        error_log_windows.iconbitmap(".\\img\\vt_logo.ico")

        error_log_scrollbar_X = Scrollbar(error_log_windows, orient=HORIZONTAL)
        error_log_scrollbar_X.pack(side=TOP, fill=X)

        error_log_scrollbar_Y = Scrollbar(error_log_windows, orient=VERTICAL)
        error_log_scrollbar_Y.pack(side=RIGHT, fill=Y)

        error_log_listbox = Listbox(
            error_log_windows,
            yscrollcommand=error_log_scrollbar_Y.set,
            xscrollcommand=error_log_scrollbar_X.set,
        )

        error_log_listbox.pack(fill=BOTH,  padx=5, pady=5)

        error_log_scrollbar_Y.config(command=error_log_listbox.yview)
        error_log_scrollbar_X.config(command=error_log_listbox.xview)

        for index, error_log in enumerate(self.error_log_list):
            error_log_listbox.insert(index, error_log)

    def show_help(self):
        """
        Show Help in a new window
        """

        help_windows = Toplevel(self.main_widows)

        help_windows.title("VIRUSTOTAL SCAN : HELP")
        help_windows.minsize(600, 480)
        help_windows.geometry("600x500")
        help_windows.iconbitmap(".\\img\\vt_logo.ico")

        help_scrollbar_X = Scrollbar(help_windows, orient=HORIZONTAL)
        help_scrollbar_X.pack(side=TOP, fill=X)

        help_scrollbar_Y = Scrollbar(help_windows, orient=VERTICAL)
        help_scrollbar_Y.pack(side=RIGHT, fill=Y)

        help_listbox = Listbox(
            help_windows,
            yscrollcommand=help_scrollbar_Y.set,
            xscrollcommand=help_scrollbar_X.set,
        )

        help_listbox.pack(fill=BOTH, padx=5, pady=5)
        help_scrollbar_Y.config(command=help_listbox.yview)
        help_scrollbar_X.config(command=help_listbox.xview)

        for index, help in enumerate(about_text.split("\n")):
            help_listbox.insert(index, help)

    def show_nok_result(self):
        """
        show nok result in a new widget
        """

        Nok_result_windows = Toplevel(self.main_widows)

        Nok_result_windows.title("VIRUSTOTAL SCAN : Nok Result")
        Nok_result_windows.minsize(600, 480)
        Nok_result_windows.geometry("600x500")
        Nok_result_windows.iconbitmap(".\\img\\vt_logo.ico")

        Nok_file_cbb = Combobox(
            Nok_result_windows, state="readonly", values=self.NOK_file_list
        )
        Nok_file_cbb.pack(fill=X, padx=5, pady=5)

        display = Label(Nok_result_windows, text="")
        display.pack(fill=X, padx=5, pady=5)

        Nok_file_cbb.bind(
            "<<ComboboxSelected>>",
            lambda event: self.update_nok_result_info(event, Nok_file_cbb, display),
        )

    def update_nok_result_info(self, event, combobox, label):
        """
        update Nok result widget label when new value selected on combobox
        """

        label_text = ""

        if combobox.current() != -1:

            json_recev = self.Nok_file_list_scan_result_dict[
                self.NOK_file_list[combobox.current()]
            ]

            for analys_engine in json_recev:

                if str(json_recev[str(analys_engine)]["detected"]) == "True":

                    print(
                        analys_engine, " : ", json_recev[str(analys_engine)]["result"]
                    )

                    label_text += (
                        str(analys_engine)
                        + " : "
                        + str(json_recev[str(analys_engine)]["result"])
                        + "\n"
                    )

            label.config(text=label_text)

        combobox.selection_clear()

    def set_force_scan(self):
        """
        set variable force scan
        """

        self.force_scan = not self.force_scan

    def clear_list(self):
        """
        clear list variable
        """

        self.NOK_file_list.clear()
        self.OK_file_list.clear()
        self.Waiting_file_list.clear()

        self.update_Nok_list(self.NOK_file_list)
        self.update_ok_list(self.OK_file_list)
        self.update_waiting_list(self.Waiting_file_list)

    def import_waiting_list(self):
        """
        import a list of file to scan
        """

        filename = askopenfilename(
            title="Ouvrir le(s) fichier(s) pour le scan", filetypes=[("save", ".pkl")]
        )
        if filename != "":
            try:
                with open(filename, "rb") as save_file:

                    self.Waiting_file_list = pickle.load(save_file)
                    self.update_waiting_list(self.Waiting_file_list)

            except Exception as ex:
                print(ex)

    def export_waiting_list(self):
        """
        export a list of file to scan
        """

        filename = asksaveasfilename(
            title="save as ...", defaultextension="*.pkl", filetypes=[("save", "*.pkl")]
        )

        if filename != "":
            try:

                with open(filename, "wb") as save_file:
                    pickle.dump(self.Waiting_file_list, save_file, 0)

            except Exception as ex:
                print(ex)

    def resize_windows(self, event):
        """
        Dynamically resize Frame, panedwindows width depend on main windows width
        Parameters
        ----------
        event : tkinter.event
        """

        if self.init_end:
            new_width = (event.width / 2) - 10
            padx = 10
            Scrollbarsize = 50

            self.ok_list_panedwindow.config(width=new_width)
            self.ok_list.config(width=int((new_width - padx) - Scrollbarsize))

            self.Waiting_list_panedwindow.config(width=new_width)
            self.Waiting_list.config(width=int((new_width - padx) - Scrollbarsize))

            self.Nok_list_panedwindow.config(width=new_width)
            self.Nok_list.config(width=int((new_width - padx) - Scrollbarsize))

            self.button_panedwindow.config(width=new_width)

    def update_waiting_list(self, files_list_name):
        """
        Clear and update waiting_list Listbox
        Parameters
        ----------
        files_list_name : list(str) 
            python list which contain a list of file path name (c:/example.py)
        """

        self.Waiting_list.delete(0, self.Waiting_list.size())

        for index, file in enumerate(files_list_name):
            self.Waiting_list.insert(index, file)

    def update_ok_list(self, files_list_name):
        """
        Clear and update ok_list Listbox
        Parameters
        ----------
        files_list_name : list(str) 
            python list which contain a list of file path name (c:/example.py)
        """

        self.ok_list.delete(0, self.ok_list.size())

        for index, file in enumerate(files_list_name):
            self.ok_list.insert(index, file)

    def update_Nok_list(self, files_list_name):
        """
        Clear and update Nok_list Listbox
        Parameters
        ----------
        files_list_name : list(str) 
            python list which contain a list of file path name (c:/example.py)
        """

        self.Nok_list.delete(0, self.Nok_list.size())

        for index, file in enumerate(files_list_name):
            self.Nok_list.insert(index, file)

    def get_all_file_in_directory(self, directory_address):
        """
        get a list of all file in the directory, 
        this fonction is recursive, please take care of it ( avoid link file =) )
        Parameters
        ----------
        directory_address : str 
            Directory name ( c:/...)

        """
        list_of_file = list("")
        for file_name in listdir(directory_address):
            dir_file = directory_address + "/" + file_name
            if isfile(dir_file) == True:
                list_of_file.append(dir_file)

            else:
                list_of_file += self.get_all_file_in_directory(dir_file)

        return list_of_file

    def close_app(self):
        """
        "Properly" close application and stop thread
        """
        _ = threading.Thread(name="stop_scan_thread", target=self.close_app_thread)
        _.start()

    def close_app_thread(self):
        if self.call_start_scan:

            self.call_start_scan = False
            self.scan_stopped = False

            self.bouton_stop_scan.config(state=DISABLED)
            self.bouton_start_scan.config(state=DISABLED)
            self.bouton_scan_file.config(state=DISABLED)
            self.bouton_scan_dir.config(state=DISABLED)
            self.bouton_delete.config(state=DISABLED)

            while not self.scan_stopped:

                self.curent_scan_file_label.config(text="Stopping scan")
                sleep(0.5)
                self.curent_scan_file_label.config(text="Stopping scan ...")
                sleep(0.5)

        self.curent_scan_file_label.config(text="")

        self.THREAD_IS_ACTIVE = False

        while not self.thread_down:
            sleep(0.2)

        self.main_widows.quit()

    def select_scan_dir(self):
        """
        Ask for directory and add all files in it to Waiting_file_list variable
        """

        directory = askdirectory(title="Ouvrir le dossier a scaner")

        if directory != "":

            self.Waiting_file_list += self.get_all_file_in_directory(directory)

            self.update_waiting_list(self.Waiting_file_list)

    def select_scan_file(self):
        """
        Ask for file(s) and add it/them to Waiting_file_list variable
        """
        filename = askopenfilenames(
            title="Ouvrir le(s) fichier(s) pour le scan",
            filetypes=[("all files", ".*")],
        )
        if filename != "":
            self.Waiting_file_list += filename

            self.update_waiting_list(self.Waiting_file_list)

    def remove_to_waiting_list(self):
        """
        Remove a file from the list of waiting file
        """
        try:

            file_to_remove = self.Waiting_list.selection_get()
            if file_to_remove != None:
                self.Waiting_file_list.remove(file_to_remove)
                self.update_waiting_list(self.Waiting_file_list)

        except Exception as ex:
            print(ex)

    def stop_scan(self):
        """
        Properly stop scan
        """
        _ = threading.Thread(name="stop_scan_thread", target=self.stop_scan_thread)
        _.start()

    def stop_scan_thread(self):
        """
        Properly stop scan
        """
        if self.call_start_scan:

            self.call_start_scan = False

            self.bouton_stop_scan.config(state=DISABLED)

            self.scan_stopped = False
            while not self.scan_stopped:

                self.curent_scan_file_label.config(text="Stopping scan")
                sleep(0.5)
                self.curent_scan_file_label.config(text="Stopping scan ...")
                sleep(0.5)

            self.curent_scan_file_label.config(text="")

            self.bouton_start_scan.config(state=NORMAL)
            self.bouton_scan_file.config(state=NORMAL)
            self.bouton_scan_dir.config(state=NORMAL)

    def start_scan(self):
        """
        Start scan function.
        """

        if len(self.Waiting_file_list) != 0:
            if self.call_start_scan == False:
                self.call_start_scan = True
                self.scan_stopped = False

    def scan_file(self):
        """
        Send all files Waiting_file_list for analysis and send them to to correct list (OK or NOK list)

        INFOMATIONS
        -------
        file_report_list [0] new scan [1] old scan (if file was already scan by you or someone else)
        status code 200 = no problem, see https://developers.virustotal.com/reference#public-vs-private-api
        File size limit is 32MB, in order to submit files up to 200MB in size you must request a special 
        upload URL using the /file/scan/upload_url endpoint
        MAX_FILE_SIZE = 32 MO
        """

        try:
            nok_file_json_result = dict()
            MAX_FILE_SIZE = 31000000
            for file in self.Waiting_file_list:

                if not self.call_start_scan:
                    raise virustotal_exception.stop_scan_call()

                self.curent_scan_file_label.config(text="Scan file : " + file)

                if getsize(file) > MAX_FILE_SIZE:
                    self.Waiting_file_list.remove(file)
                    self.update_waiting_list(self.Waiting_file_list)

                    print("===================================")
                    print("file :", file, " ; size > 32MB")

                    self.error_log_list.append("file :\n")
                    self.error_log_list.append(file)
                    self.error_log_list.append("\nOver limit size (file size > 32MB)")
                    self.error_log_list.append(
                        "\n============================================\n"
                    )

                else:

                    scan_file_needed = True
                    check_report_loop = True
                    file_positive = 0

                    # get sha256
                    scan_sha256 = ""

                    with open(file, "rb") as file_test:
                        hash_sha_256 = sha256()
                        hash_sha_256.update(file_test.read())

                        scan_sha256 = str(hash_sha_256.hexdigest())

                    if self.force_scan:
                        check_report_loop = False
                        scan_file_needed = True
                    else:
                        check_report_loop = True

                    # check report
                    while check_report_loop:

                        if not self.call_start_scan:
                            raise virustotal_exception.stop_scan_call()

                        file_report = vtotal.file_report([scan_sha256])

                        if file_report["status_code"] == 200:

                            try:
                                scan_date = file_report["json_resp"]["scan_date"]

                                scan_date_years = int(scan_date.split("-")[0])
                                scan_date_month = int(scan_date.split("-")[1])
                                scan_date_day = int(
                                    scan_date.split("-")[2].split(" ")[0]
                                )
                                scan_date = datetime.datetime(
                                    year=scan_date_years,
                                    month=scan_date_month,
                                    day=scan_date_day,
                                )

                                if (
                                    datetime.datetime.now() - scan_date
                                ) < datetime.timedelta(days=14):

                                    file_positive += file_report["json_resp"][
                                        "positives"
                                    ]
                                    scan_file_needed = False

                                    if file_report["json_resp"]["positives"] != 0:

                                        nok_file_json_result = file_report["json_resp"][
                                            "scans"
                                        ]

                                else:
                                    scan_file_needed = True

                            except KeyError as ker:
                                print("file", file, "never scan")
                                print(ker, "not found")
                                scan_file_needed = True

                            check_report_loop = False

                        elif file_report["status_code"] == 204:
                            # https://developers.virustotal.com/reference#public-vs-private-api
                            print("Request rate limit exceeded")
                            print("File :", file)
                            sleep(10)

                        else:

                            print("===================================")
                            print("ERROR on file :")
                            print(file)
                            print("JSON received :")
                            print(file_report)

                            self.error_log_list.append("ERROR on file :\n")
                            self.error_log_list.append(file)
                            self.error_log_list.append("\nJSON received :\n")
                            self.error_log_list.append(file_report)
                            self.error_log_list.append(
                                "\n============================================\n"
                            )
                            sleep(1)

                        sleep(1)

                    # scan file
                    if scan_file_needed:

                        json_resp_loop = True

                        while json_resp_loop:

                            file_request = vtotal.file_scan(file)

                            if file_request["status_code"] == 200:

                                file_info = file_request["json_resp"]
                                scan_id = str(file_info["scan_id"])
                                scan_sha256 = str(file_info["sha256"])

                                sleep(5)

                                file_report = vtotal.file_report([scan_id, scan_sha256])

                                json_resp = file_report["json_resp"]

                                if str(json_resp[0]["response_code"]) != "-2":

                                    file_positive += file_report["json_resp"][0][
                                        "positives"
                                    ]

                                else:

                                    while str(json_resp[0]["response_code"]) == "-2":
                                        sleep(5)
                                        file_report = vtotal.file_report(
                                            [scan_id, scan_sha256]
                                        )

                                        if file_report["status_code"] == 200:
                                            json_resp = file_report["json_resp"]

                                    file_positive += file_report["json_resp"][0][
                                        "positives"
                                    ]

                                    if file_report["json_resp"]["positives"] != 0:

                                        nok_file_json_result = file_report["json_resp"][
                                            "scans"
                                        ]

                                json_resp_loop = False

                            else:

                                print("===================================")
                                print("NOK file :")
                                print(file)
                                print("JSON received :")
                                print(file_report)

                                self.error_log_list.append("NOK file :\n")
                                self.error_log_list.append(file)
                                self.error_log_list.append("\nJSON received :\n")
                                self.error_log_list.append(file_report)
                                self.error_log_list.append(
                                    "\n============================================\n"
                                )

                                sleep(2)

                    self.Waiting_file_list.remove(file)
                    self.update_waiting_list(self.Waiting_file_list)

                    if file_positive == 0:
                        self.OK_file_list.append(file)
                        self.update_ok_list(self.OK_file_list)

                    else:
                        self.NOK_file_list.append(file)
                        self.update_Nok_list(self.NOK_file_list)

                        self.Nok_file_list_scan_result_dict[file] = nok_file_json_result

                self.curent_scan_file_label.config(text="")

            if len(self.Waiting_file_list) != 0:
                self.scan_file()

            self.call_start_scan = False
            self.scan_stopped = True

        except virustotal_exception.stop_scan_call:
            print("stop scan called")
            self.scan_stopped = True
            self.call_start_scan = False

        except Exception as ex:
            print(ex)
            raise ex
