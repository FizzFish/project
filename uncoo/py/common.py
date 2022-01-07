import logging

class Logger:
    def __init__(self, module):
        self.logger = logging.getLogger(module)
        self.logger.setLevel(logging.INFO)

        #fh = logging.FileHandler('log', mode='w')
        fh = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - [%(filename)s:%(lineno)d] - %(message)s")
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        """
        self.logger.removeHandler(fh)
        fh.close()
        """

    def getlogger(self):
        return self.logger
        
def simple(path):
    return path[path.rfind('/')+1:]
