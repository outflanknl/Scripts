function PowerSpeak
{
<#
.SYNOPSIS
PowerSpeak is a PowerShell interface for the Windows Speech interface that exists since Windows XP.

It is not an interface for Cortana.

TODO: fix that the user is presented the Speech Wizard after re-login.

Function: PowerSpeak
Author: Marc Smeets


.DESCRIPTION
PowerSpeak can be used for sending text to speech using the Windows Speech interface.

.PARAMETER Test
Test if system is capable of speaking.

.PARAMETER Speak
The text to speak. Enclose with quotes if more than 1 word.


.EXAMPLE
PS > PowerSpeak -Test
This will try to start the Windows Speech interface and display its state.

.EXAMPLE
PS > PowerSpeak Hello
This will speak the single word "Hello".

.EXAMPLE
PS > PowerSpeak Hello -Volume 50
This will speak the single word "Hello" at half volume. 
If Volume is not specified it will be set to max and reset to previous value when done speaking.


.EXAMPLE
PS > PowerSpeak "Look! It's moving. It's alive. It's alive... IT'S ALIVE!"
Using quotes we can speak sentences.


.LINK
http://www.outflank.nl

#>
	[CmdletBinding()] 
	Param(
		[Parameter(Position=0, Mandatory = $False)]
		[String]
		$Speak,

		[Switch]$Test,

		[Parameter(Mandatory = $False)]
		[ValidateRange(0,100)]
		[Int]
		$Volume=100
    )

	if ($Test)
	{
		$PowerSpeak|gm
	}

	if ($Speak)
    {
	try
	{
		$oldvolume = $PowerSpeak.volume
		$PowerSpeak.Volume = $Volume
		$PowerSpeak.speak($Speak)
		$PowerSpeak.volume = $oldvolume
	}
	catch
	{
		$PowerSpeak.volume = $oldvolume
		write-host "Error sending speak command."
	}
	}
}

try
{
    add-type -assemblyname system.speech
    $PowerSpeak = New-Object System.Speech.Synthesis.SpeechSynthesizer
}
catch
{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    write-host "Error loading Windows Speech interface."
    write-host $errormessage
    write-host $faileditem
    break
}
