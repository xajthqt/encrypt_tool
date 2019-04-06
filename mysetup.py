import py2exe
from distutils.core import setup

options = {"py2exe":  
            {   "compressed": 1,  
                "optimize": 2,   
                #"bundle_files": 1  
            }  
          }  
setup(     
    version = "0.1.0",  
    description = "search panda",  
    name = "CreatLicence",  
    options = options,  
    zipfile=None,  
    windows=[{"script": "CreatLicense.py", "icon_resources": [(0, "bitbug_favicon.ico")] }],    
      
    )
#通过命令行进入到当前目录 setup.py  py2exe
#密钥4096
