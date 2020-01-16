class stop_scan_call(Exception):
    """
    exeption raised when stop scan is called
    """
    def __init__(self,*args,**kwargs):
        super().__init__(self,*args,**kwargs)