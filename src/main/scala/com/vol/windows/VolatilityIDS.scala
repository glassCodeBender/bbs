package com.bbs.vol.windows

/**
  * @ J. Alexander
  * @version 1.0
  *
  *          Contains main method of program.
  */

/**
  * TO DO
  * ** Write ethscan analysis
  * ** Look for executables disguised as non-executables. WordDoc.docx.exe
  * ** Look for commonly changed fileNames (e.g. svchost.exe)
  * ** Consider IDT (369)
  * ** Check if module loaded from temp path
  * ** Examine module's path
  * ** Compare driverscan Start address to modules base address. They should match.
  * ** Extract start address from orphan thread, determine which process thread is located in. (How do you get exec end address?)
  *
  * AFTER REPORT PRODUCED:
  * ** Extract DNS cache (340)
  */

import scala.io.Source
import sys.process._
import java.io.File
import java.util.Calendar

import com.bbs.vol.processtree._

import scala.collection.immutable.TreeMap
import com.bbs.vol.windows.StringOperations._

import scala.collection.mutable
import scala.util.Try

object VolatilityIDS {
  /*****************************************************
    ****************************************************
    ******************~~~~~MAIN~~~~*********************
    ****************************************************
    ****************************************************/
  def main( args: Array[String] ): Unit = {

    // Need to read in user input from a config file.

    val (os, memFile) = parseConfig()

    /**
      * Check and make sure valid file extension
      */

    // when we read in the config file, we need to make sure memFile doesn't have spaces in it.
    // If it does, we need to add quotes around it.

    if ( os.startsWith( "WinXP" ) || os.startsWith( "Win2003" ) ) {

    }

    val fileBool: (Boolean, String) = checkDir( memFile )

    /** Check and make sure the memory file is valid */
    if ( fileBool._1 == false ) {
      println( "The memory file you entered does not exist.\n\n" +
        s"Check and make sure ${fileBool._2} is the correct file name.\n\nExiting program..." )
      System.exit( 1 )
    }

    /** This will be replaced w/ a timer if I have time. */
    val kdbg = checkKDBG( memFile )

    /** Make a directory to store log, prefetch, and pcap output as txt by volatility */
    val dumpDir = mkDir( memFile )

    /** Broadly examine image for malicious behavior. */
    val discoveryResult: Discovery = VolDiscoveryWindows.run( memFile, os, dumpDir )

    /** discoveryResult Contains:
      *
      * final case class Discovery(
      *                  proc: (Vector[Process], String),               // (All process info, processTree)
      *                  sysState: SysState,                            // SysState
      *                  net: (Vector[NetConnections], Vector[String]), // (connection Info, Whois Lookup)
      *                  rootkit: RootkitResults,                       // RootkitResults
      *                  remoteMapped: Vector[(String, String)],        // (pid -> RemoteMappedDrive Found)
      *                  registry: (Vector[String], Vector[String])     // (User Registry, System Registry)
      *                  )
      */

    val process: Vector[ProcessBbs] = discoveryResult.proc._1
    val netConns = discoveryResult.net._1

    /** Examine individual processes */
    val processDiscovery = ProcessDiscoveryWindows.run(os, memFile, process, netConns)

    /** Search for hidden executables. */
    val hiddenExecs = findHiddenExecs(process)
    /** Determine overall risk rating for memory image */
    val riskRating = FindSuspiciousProcesses.run(discoveryResult, processDiscovery)


    /** Need to write extract parts of Discovery (proc), and pass it to next section of program. */

  } // END main()

  /****************************************************************************************/
  /***************************************** END main() ***********************************/
  /****************************************************************************************/

  /** Parses the config file. */
  private[this] def parseConfig( ): (String, String) = {

    val fileName = System.getProperty("user.dir") + "/" + "bbs_config.txt"
    val src = Source.fromFile( fileName )
    val readConfig = src.getLines.filterNot( _.contains( "#" ) )
      .toVector
    src.close

    val splitUp: Vector[String] = readConfig.flatMap( _.split( "~>" ) )
    val cleanSplit = splitUp.map( _.trim )
    if ( cleanSplit.size == 4 ) {
      println( "\n\nWelcome to the Big Brain Security Volatile IDS! \n" +
        "\nReading bbs_config.txt file to determine your settings...\n\n" +
        "\nThe configuration file was successfully read...\n\nRunning the program..." )
    }  else System.exit( 1 )

    return (cleanSplit(1), cleanSplit(3))
  } // END parseConfig()

  /** Creates a directory where we'll store log, prefetch, and pcap info in txt files */
  private[windows] def mkDir(memFile: String): String = {
    val cal = Calendar.getInstance()
    val date = {
      cal.get(Calendar.MONTH) + "-" + cal.get(Calendar.DATE) + "_" + cal.get(Calendar.HOUR) + cal.get(Calendar.MINUTE)
    }
    val dirName = System.getProperty("user.dir") + "/" + memFile + date
    val dir = new File(dirName)
    // val checkCreation: Boolean = dir.mkdir()

    if(dir.mkdir()){
      println(s"Log files, prefetch files, mft, and pcaps will be located in the following directory:\n$dirName")
    } else{
      println("\n\n\nWe failed to create a directory for lots of helpful information. Check and make sure\n" +
        s"the directory $dirName doesn't already exist.\n\n")
    }
    val shortDirName = memFile + date

    return shortDirName
  } // END mkDir()

  /** Determines where output will be stored. */
  private[windows] def checkDir(memFile: String): (Boolean, String) =
  {
    val currentDir = System.getProperty("user.dir") + "/" + memFile

    /* Need to make sure there are no spaces in the directory, if there are, add quotes at beginning of first and end of second word. */

    val file = new File(currentDir)
    val fileBool = file.exists()

    return (fileBool, currentDir)
  } // END checkDir

  /** Checking to make sure the memory dump provided isn't corrupted. This will probably be removed soon. */
  private[this] def checkKDBG( memFile: String ) = {

    println(
      "\nBefore the program runs, we first need to verify that your image is not corrupted.\n\n" +
      "WARNING: If the program does not print information about your image to the console in 2-3 minutes,\n" +
      "it is likely that the image was damaged during extraction and the program will run indefinitely.\n\n" +
      "If information about the image does not print to the console in 2-3 minutes, it is likely you made an error while " +
      "extracting the memory, a rootkit prevented you from dumping the memory, or the image file is not in the volatility-master directory.\n\n" +
      "To test your image, open the console and type the following:\n\t" +
      s">> python vol.py -f $memFile imageinfo\n\n" )

    // val imageInfo: Option[String] = Some( s"python vol.py -f $memFile imageinfo".!!.trim )

    val imageInfo = Some("")
    print(imageInfo.getOrElse(""))
  }

  /** Looks for hidden executables. */
  private[this] def findHiddenExecs(vec: Vector[ProcessBbs]): Vector[String] = {

    val hiddenExecPattern = {
      Vector(".+//.xlsx.exe", ".+//.csv.exe", ".+//.doc.exe", ".+//.xls.exe", ".+//.xltx.exe", ".+//.xlt.exe",
        ".+//.pdf.exe", ".+//.xlsb.exe", ".+//.xlsm.exe", ".+//.xlst.exe", ".+//.xml.exe", ".+//.txt.exe",
        ".+//.ods.exe", ".+//.docx.exe", ".+//.dot.exe", ".+//.rtf.exe", ".+//.docm.exe", ".+//.dotm.exe",
        ".+//.htm.exe", ".+//.mht.exe", ".+//.jpg.exe", ".+//.ppt.exe", ".+//.pptx.exe", ".+//.pot.exe",
        ".+//.odp.exe", ".+//.ppsx.exe", ".+//.pps.exe", ".+//.pptm.exe", ".+//.potm.exe", ".+//.ppsm.exe",
        ".+//.py.exe", ".+//.pl.exe", ".+//.eml.exe", ".+//.json.exe", ".+//.mp3.exe", ".+//.wav.exe", ".+//.aiff.exe",
        ".+//.au.exe", ".+//.pcm.exe", ".+//.ape.exe", ".+//.wv.exe", ".+//.m4a.exe", ".+//.8svf.exe", ".+//.webm.exe",
        ".+//.wv.exe", ".+//.wma.exe", ".+//.vox.exe", ".+//.tta.exe", ".+//.sln.exe", ".+//.raw.exe", ".+//.rm.exe",
        ".+//.ra.exe", ".+//.opus.exe", ".+//.ogg.exe", ".+//.oga.exe", ".+//.mogg.exe", ".+//.msv.exe", ".+//.mpc.exe",
        ".+//.mmf.exe", ".+//.m4b.exe", ".+//.ivs.exe", ".+//.ilkax.exe", ".+//.gsm.exe", ".+//.flac.exe",
        ".+//.dvf.exe", ".+//.dss.exe", ".+//.dct.exe", ".+//.awb.exe", ".+//.amr.exe", ".+//.act.exe", ".+//.aax.exe",
        ".+//.aa.exe", ".+//.3gp.exe", ".+//.webm.exe", ".+//.mkv.exe", ".+//.flv.exe", ".+//.vob.exe", ".+//.ogv.exe",
        ".+//.ogg.exe", ".+//.gif.exe", ".+//.gifv.exe", ".+//.mng.exe", ".+//.avi.exe", ".+//.mov.exe", ".+//.qt.exe",
        ".+//.wmv.exe", ".+//.yuv.exe", ".+//.rm.exe", ".+//.rmvb.exe", ".+//.asf.exe", ".+//.amv.exe", ".+//.mp4.exe",
        ".+//.m4p.exe", ".+//.m4v.exe", ".+//.amv.exe", ".+//.asf.exe")
    } // END hiddenExecPattern

    /** Combine all the strings in the Vector to make a single regex */
    val makeRegex = "(" + hiddenExecPattern.mkString("|") + ")"
    val regex = makeRegex.r

    /** Vector of process names. */
    val procVec: Vector[String] = vec.map(x => x.name).distinct
    val searchForHiddenProcs = procVec.map(x => regex.findFirstIn(x).getOrElse("None"))
    val hiddenProcs = searchForHiddenProcs.filterNot(x => x.contains("None"))
    if(hiddenProcs.nonEmpty) {
      println("\nPrinting hidden executables.\n\n")
      hiddenProcs.foreach(println)
    }

    return hiddenProcs
  } // END hiddenExecPattern

  /**
    * This map will be periodically updated. I'm hoping that about 75% of the processes on regular systems will be
    * included in this list so that the program doesn't have to repeatedly call large TreeMaps
    *
    * Need to Add:
    * VNC
    * cain and abel
    * pwdump
    * fgdump
    * meterpreter hashdump script (pretty sure doesn't show up as process)
    * alg.exe
    * excel
    * slack
    * itunes
    * opera
    * spotify
    * pandora
    * powerpoint
    * cmd.exe
    * notepad.exe
    * onenote
    * word processors (open office)
    * publisher
    * onedrive
    * wireshark
    * quicktime
    * outlook
    * cortana
    */
  /** This Map of processes was created to avoid the computationally expensive lookup from the main process database.
    * The program will first check this list before looking in the massive database of processes.
    * This list also makes it easier to ensure that the information provided is accurate since it's easy to check.
    */
  private[windows] def commonProcesses(): Map[String, String] = {
    val procMap = Map[String, String](
    "SVCHOST.EXE" -> "The file svchost.exe is the Generic Host Process responsible for creating Services. Attackers commonly inject code into this process.",
    "CSRSS.EXE" -> "The Microsoft Client Server Runtime Server subsystem utilizes the process for managing the majorify of the graphical instruction sets under the Microsoft Windows operating system. As such Csrss.exe provides the critical functions of the operating system. Csrss.exe controls threading and Win32 console window features.",
    "WINLOGON.EXE" -> "winlogon.exe is a process belonging to the Windows login manager. It handles the login and logout procedures on your system.",
    "ADSERVICE.EXE" -> "Active Disk Service is a component of the Iomega zip drive.",
    "APPSERVICES.EXE" -> "For the Iomega zip drive.",
    "MSIMN.EXE" -> "Outlook Express",
    "CCSETMGR.EXE" -> "Also associated with Symantec’s Internet Security Suite. Keep it and protect your PC.",
    "CSRSS.EXE" -> " System process that is the main executable for the Microsoft Client / Server Runtim Server Subsystem. It should not be shut down.",
    "CTFMON.EXE" -> " non-essential system process. If you’re using only English as the language, then it is not needed. However, it’s recommended to leave it alone.",
    "EXPLORER.EXE" -> " This must always be running in the background. It’s a user interface process that runs the windows graphical shell for the desktop, task bar, and Start menu.",
    "IEXPLORE.EXE" -> " Internet Explorer browser. But why are you using it unless it’s for a site that doesn’t work in any other browser? Use Firefox instead.",
    "LSASS.EXE" -> "Security Authority Service is a Windows security related system process for handling local security and login policies.",
    "NC.EXE" -> "Netcat listener. Commonly used by hackers to create backdoors. Also used by for sharing files and other tasks.",
    "NAVAPSVC.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "NVSRVC32.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "NAVAPW32.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "REALSCHED.EXE" -> "RealNetworks Scheduler is not an essential process. It checks for updates for RealNetworks products. It can be safely disabled.",
    "RUNDLL32.EXE" -> "A system process that executes DLLs and loads their libraries.",
    "SAVSCAN.EXE" -> "Nortons AntiVirus process.",

      "SEARCHINDEXER.EXE" -> "Standard Windows process",
      "WMIPRVSE.EXE" -> "Standard Windows Process.",
      "TASKLIST.EXE" -> "Executable used to grab Windows processes",
      "SEARCHUI.EXE" -> "Standard Windows process.",
      "SKYPEHOST.EXE" -> "Skype",
      "ONEDRIVE.EXE" -> "Microsoft OneDrive",
      "MSASCUIL.EXE" -> "Standard Windows process.",
      "SHELLEXPERIENCEHOST.EXE" -> "Standard Windows process.",
      "RUNTIMEBROKER.EXE" -> "Standard Windows process.",
      "NISSRV.EXE" -> "Standard",
      "BACKGROUNDTASKHOST.EXE" -> "Standard Windows process.",
      "POWERSHELL.EXE" -> "Windows Powershell",
      "VMTOOLSD.EXE" -> "VMware Tools.",
      "VMACTHLP.EXE" -> "VMware Physical Disk Helper",
      "DWM.EXE" -> "Standard Windows process.",
      "MICROSOFTEDGE.EXE" -> "Microsoft Edge",
      "MICROSOFTEDGECP.EXE" -> "Microsoft Edge",
      "INSTALLAGENT.EXE" -> "",
      "BROWSER_BROKER.EXE" -> "Used for web browsers",
      "SNIPPINGTOOL.EXE" -> "Windows Snipping Tool",
      "HXCALENDARAPPIMM.EXE" -> "Windows Calendar",
      "HXTSR.EXE" -> "Windows Calendar",
      "CALCULATOR.EXE" -> "Windows Calculator",
      "WINDOWSCAMERA.EXE" -> "Windows Webcam Program",
      "ONENOTEIM.EXE" -> "Microsoft OneNote",
      "SOLITAIRE.EXE" -> "Microsoft Solitaire",
      "GAMEBARPRESENCEWRITER.EXE" -> "Used for Microsoft games like Solitaire",
      "MUSIC.UI.EXE" -> "Groove Music",
      "MICROSOFT.PHOTOS.EXE" -> "Microsoft Photos",
      "AUDIODG.EXE" -> "Microsoft Audio",
      "MAPS.EXE" -> "Microsoft maps",
      "SOUNDREC.EXE" -> "Microsoft Sound Recorder",
      "WINSTORE.APP.EXE" -> "Microsoft Application Store",
      "WMPLAYER.EXE" -> "Windows Media Player",
      "SYNTPENH.EXE" -> "Synaptics TouchPad 64 bit enhancements",
      "SYNTPHELPER.EXE" -> "Synaptics Pointing Device Helper",
      "SIHOST.EXE" -> "Microsoft Shell Infrastructure Host",
      "CONHOST.EXE" -> "Console Window Host",
      "MSMPENG.EXE" -> "Windows Defender Background Tasks",
      "TASKHOSTW.EXE" -> "Starts Windows services when OS starts up. For Windows 10 only.",
      "TASKHOSTEX.EXE" -> "Starts Windows services when OS starts up. For Windows 8 only.",
      "TASKHOST.EXE" -> "Starts Windows services when OS starts up. For Windows 7 only.",

    "SERVICES.EXE" -> "An essential process that manages the starting and stopping of services including the those in boot up and shut down. Do not terminate it.",
    "SMSS.EXE" -> " Session Manager SubSystem is a system process that is a central part of the Windows operating system.",
    "SPOOLSV.EXE" -> " Microsoft printer spooler service handles local printer processes. It’s a system file.",
    "SVCHOST.EXE" -> " You may have more than six appearances of this process or less. It’s there multiple times to handle processes executed from DLLs. Leave it there.",
    "SYSTEM" -> " This is a file that stores information related to local hardware settings in the registry under ‘HKEY_LOCAL_MACHINE’. Kill it and kiss your PC’s stability bye bye.",
    "SYSTEM IDELE PROCESS" -> "Calculates the amount of CPU currently in use by applications. This won’t go away no matter how hard you try. Don’t try it, OK?",
    "TASKMGR.EXE" -> "Task Manager. Appears when you press Ctrl+Alt+Del.",
    "WDFMGR.EXE" -> " Windows Driver Foundation Manager is part of Windows media player 10 and newer. Better not to stop the process.",
    "WINLOGON.EXE" -> " Handles the login and logout processes. It’s essential.",
    "WINWORD.EXE" -> " Microsoft word.",
    "FIREFOX.EXE" -> "Firefox browser",
    "CHROME.EXE" -> "Google chrome browser",
    "ADOBEARM.EXE" -> "Belongs to Adobe Acrobat and Adobe Reader. The process runs in the background and checks for updates to Adobe products.",
    "DIVXUPDATE.EXE" -> "Runs in the background and checks for updates to DivX Plus. You can simply terminate the updater; it launches automatically when you open any DivX program.",
    "WINWORD.EXE" -> " Microsoft word.",
    "FIREFOX.EXE" -> "Firefox browser",
    "CHROME.EXE" -> "Google chrome browser",
    "PSEXEC.EXE" -> "PsExec provides utilities like Telnet and remote control programs like Symantec's PC Anywhere. Commonly used by hackers",
    "WCE.EXE" -> "Windows Credential Editor is a security tool to list logon sessions and add, change, list, and delete associated credentials. Can be used to perform pass-the-hash and obtain security credentials",
    "SAMINSIDE.EXE" -> "A program that allows users to both recover and crack Windows password hashes. Commonly used by hackers.",
    "WC.EXE" -> "Windows Credential Editor is a security tool to list logon sessions and add, change, list, and delete associated credentials. Can be used to perform pass-the-hash and obtain security credentials",
    "CCEVTMRG.EXE" -> "Associated with Symantec’s Internet Security Suite. Keep it and protect your PC.",
    "READER_SL.EXE" -> "Part of Adobe Reader and stands for Adobe Acrobat Speed Launcher. It speeds up the launch of the reader, but isn’t actually necessary.",
    "JQS.EXE" -> "Accelerates the launch of almost all software that works with Java. The Java Quick Starter isn’t really necessary.",
    "OSA.EXE" -> "Enables some Microsoft Office programs in Windows XP to launch more quickly and anchors certain Office functions to the start menu. The Office Source Engine may be of interest to regular Office users, but probably not to others.",
    "SOFFICE.EXE" -> "Fulfills the same purpose as Osa.exe, but for the Office packages StarOffice and OpenOffice.",
    "ADOBEARM.EXE" -> "Belongs to Adobe Acrobat and Adobe Reader. The process runs in the background and checks for updates to Adobe products.",
    "JUSCHED.EXE" -> "Stands for Java Update Scheduler. Once a month, the process checks whether there is a new update for Java, which is quite infrequent for a process that’s always running.",
    "DIVXUPDATE.EXE" -> "Runs in the background and checks for updates to DivX Plus. You can simply terminate the updater; it launches automatically when you open any DivX program.",
    "NEROCHECK.EXE" -> "Searches for drivers that could trigger conflicts with Nero Express, Nero, and NeroVision Express. You can also start this service manually if necessary.",
    "HKCMD.EXE" -> "Accompanies Intel hardware. The process allows the user to allocate any function to the keys, but also often leads to a sluggish system.",
    "ATIPTAXX.EXE" -> "Comes with ATI video card drivers. The processes provide faster access to the graphics card settings on the taskbar or individual keys.",
    "ATI2EVXX.EXE" -> "Comes with ATI video card drivers. The processes provide faster access to the graphics card settings on the taskbar or individual keys.",
    "RAVCPL64.EXE" -> "Realtek HD Audio Manager. The process detects which audio devices are connected to your computer, including headphones or a microphone. Conveniently, the devices are also recognized without the process and will run anyway.",
    "NWIZ.EXE" -> "Usually accompanies a NVIDIA graphics card.",
    "CCC.EXE" -> "ATI Catalyst Control Center. For gamers and users with higher demands for the graphic settings on their PC, this is certainly interesting; for everyone else, it’s not necessary.",
    "SYNTPENH.EXE" -> "Is used on many laptops and has drivers for touchpads, but Windows can provide these too. In addition, Synaptics TouchPad Enhancements is a known solution for stability problems.",
    "WINAMPA.EXE" -> "Places Winamp to the right at the bottom of the taskbar and makes sure that no other programs with media content are linked.",
    "ITUNESHELPER.EXE" -> "works in the background for iTunes and QuickTime. If the process runs without these programs, it can be stopped safely -- iTunes starts it automatically if needed.",
    "IPODSERVICE.EXE" -> "Works in the background for iTunes and QuickTime. If the process runs without these programs, it can be stopped safely -- iTunes starts it automatically if needed.",
    "OSPPSVC.EXE" -> "Comes with Microsoft Office 2010. The Office Software Protection Platform verifies that Office still has a valid licence.",
    "SIDEBAR.EXE" -> "Makes the practical widgets on Windows 7 and Vista possible, but also eats up a lot of memory. Anyone who doesn’t use the widgets can stop Sidebar.exe.",
    "WMPNETWK.EXE" -> "Searches the network for media files in order to populate them into Windows Media Player. If you don’t use the media player, or don’t want to search for new files, you can stop the service.",
    "JUSCHED.EXE" -> "Stands for Java Update Scheduler. Once a month, the process checks whether there is a new update for Java, which is quite infrequent for a process that’s always running.",
    "ATIPTAXX.EXE" -> "Comes with ATI video card drivers. The processes provide faster access to the graphics card settings on the taskbar or individual keys.",
    "ATI2EVXX.EXE" -> "Comes with ATI video card drivers. The processes provide faster access to the graphics card settings on the taskbar or individual keys.",
    "ITUNESHELPER.EXE" -> "works in the background for iTunes and QuickTime. If the process runs without these programs, it can be stopped safely -- iTunes starts it automatically if needed.",
    "IPODSERVICE.EXE" -> "Works in the background for iTunes and QuickTime. If the process runs without these programs, it can be stopped safely -- iTunes starts it automatically if needed."
    )

    return procMap
  } // END commonProcesses()

} // END VolatilityIDS object

/****************************************************************************************************/
/****************************************************************************************************/
/*********************************** ProcessDescription Object **************************************/
/****************************************************************************************************/
/****************************************************************************************************/

object ProcessDescription {

  private[windows] def get( processName: String ): String = {
    val firstTwo = processName.take( 2 )
    val byteInt = firstTwo.getBytes()
      .map( x => x.toInt.toString ).foldLeft( "" )( ( x, y ) => x + y ).toInt

    val tree: TreeMap[String, String] = matchProcess( byteInt )
    val description = tree( processName )

    return description
  } // get()

  /** This is an example of how we'll retrieve the process description. */
  private[this] def matchProcess( byteInt: Int ): TreeMap[String, String] = {

    val value = byteInt
    var result = new TreeMap[String, String]()

    if (4848 until 6575 contains value) result = Proc00AK.get()
    else if (6585 until 6682 contains value) result = ProcAUBR.get()
    else if (6683 until 6773 contains value) result = ProcBSCI.get()
    else if (6774 until 6778 contains value) result = ProcCJCN.get()
    else if (6779 until 6787 contains value) result = ProcCOCW.get()
    else if (6787 until 6875 contains value) result = ProcCXDK.get()
    else if (6876 until 6973 contains value) result = ProcDLEI.get()
    else if (6974 until 7072 contains value) result = ProcEJFH.get()
    else if (7073 until 7279 contains value) result = ProcFIHO.get()
    else if (7280 until 7367 contains value) result = ProcHPIC.get()
    else if (7368 until 7378 contains value) result = ProcIDIN.get()
    else if (7379 until 7576 contains value) result = ProcIOKL.get()
    else if (7577 until 7676 contains value) result = ProcKMLL.get()
    else if (7677 until 7766 contains value) result = ProcLMMB.get()
    else if (7767 until 7775 contains value) result = ProcMCMK.get()
    else if (7776 until 7788 contains value) result = ProcMLMX.get()
    else if (7789 until 7880 contains value) result = ProcMYNP.get()
    else if (7881 until 7982 contains value) result = ProcNQOR.get()
    else if (7983 until 8070 contains value) result = ProcOSPF.get()
    else if (8071 until 8082 contains value) result = ProcPGPR.get()
    else if (8083 until 8265 contains value) result = ProcPRRA.get()
    else if (8266 until 8280 contains value) result = ProcRBRP.get()
    else if (8281 until 8367 contains value) result = ProcRRSC.get()
    else if (8368 until 8375 contains value) result = ProcSDSK.get()
    else if (8376 until 8383 contains value) result = ProcSLSS.get()
    else if (8384 until 8466 contains value) result = ProcSTTB.get()
    else if (8467 until 8483 contains value) result = ProcTCTS.get()
    else if (8484 until 8667 contains value) result = ProcTTVC.get()
    else if (8668 until 8766 contains value) result = ProcVDWB.get()
    else if (8767 until 8782 contains value) result = ProcWCWR.get()
    else if (8783 until 9090 contains value) result = ProcWSZZ.get()

    return result
  } // END matchProcess()

} // END ProcessDescription object

/** Contains info that will help determine which info to print in report and the risk the system faces. */
final case class RiskRating(riskRating: Integer)

/** Class looks at the results of previous scans and determines if indicators of a breach were found. */
object FindSuspiciousProcesses {

  def run(disc: Discovery, process: ProcessBrain): Int = {

    /** */
    var riskRating = 0

    /**
      * Get info from Discovery case class
      */

    /** *******************************************************
      * Console commands should be given risk rating in a map.
      * *******************************************************/

    // YaraParseString(rule, proc, str)
    // YaraParse(classification, rule, owner, offset)
    val proc: Vector[ProcessBbs] = disc.proc._1
    /** callbacks, hiddenModules, timers, deviceTree, orphanThread, found */
    val rootkit: RootkitResults = disc.rootkit
    /** (pid -> Remote Mapped Drive) */
    val remoteMapped: Vector[(String, String)] = disc.remoteMapped
    /** Vector[String], Vector[String] */
    val registry = disc.registry
    /** svcStopped, suspCmds */
    val sysSt: SysState = disc.sysState
    val shim = disc.shimCache

    val net: Vector[NetConnections] = disc.net._1

    /**
      * Get info from ProcessBrain
      */
    val yaraObj: YaraBrain = process.yara
    val regPersist: Vector[RegPersistenceInfo] = process.regPersistence // done
    val ldr: Vector[LdrInfo] = process.ldrInfo // done
    val privs: Vector[Privileges] = process.privs // done

    val promiscModeMap: Map[String, Boolean] = process.promiscMode


    /**
      * Here is where we do the work
      *
      * NOTE: We should probably return tuples. (Info for printing report, Risk Rating)
      */

    /** Check privileges risk */
    val privRating: Int = checkPrivs(privs)

    println("Risk Rating for privileges: " + privRating.toString)

    // Update risk rating
    riskRating = riskRating + privRating

    /** Check for memory leaks */
    //  val regPersistRating: Int = checkRegPersistence(regPersist)

    // println("Risk rating for registry persistence check: " + regPersistRating.toString )

    // Update risk rating
    // riskRating = riskRating + regPersistRating

    /** Check for unlinked DLLs */

    val unlinkedDlls = checkLdr(ldr)

    println("Risk rating from unlinked DLLs: " + unlinkedDlls.toString)

    // Update risk rating
    riskRating = riskRating + unlinkedDlls

    /** Check for remote mapped drives */

    val remoteMappedRisk = checkRemoteMapped(remoteMapped)

    /** Contains risk value */
    val (shimRisk, shimCacheTime): (Int, Vector[ShimCache]) = checkShimCacheTime(shim)
    riskRating = riskRating + shimRisk
    /**
      * Need to look at the parents of hidden processes. Is it cmd.exe or powershell.exe?
      */


    /**
      * TO DO:
      * Remote Mapped Drive Scan
      * Hidden DLL
      * Registry Persistence - RUN key
      * meterpreter DLL
      * consoles
      * Look at prefetch key
      * Hidden Processes
      * Enabled Privileges
      * Stopped Suspicious Services
      * Analyze envars
      * Rootkit Detector
      * - Orphan Threads
      * - Hidden Modules
      * - Unloaded Modules
      * - Timers to Unknown Modules
      * - callbacks
      * Yara Scan Results
      * - Packers
      * - Anti-Debug
      * - Exploit Kits
      * - Webshells
      * - CVEs
      * - Malicious Documents
      * - Suspicious Strings
      * - Malware
      * - XOR (RESEARCH)
      * - Magic (Research)
      */

    return riskRating
  } // END run()

  private[this] def checkPrivs(vec: Vector[Privileges]): Int = {

    var rating = 0
    /** We only want suspicious privs for now. */
    val foundPrivs = for {
      value <- vec
      if value.suspiciousPrivs.nonEmpty
    } yield value

    val debugPrivs = for {
      value <- vec
      if value.debugPriv
    } yield value

    if (foundPrivs.nonEmpty) rating = foundPrivs.size
    if (debugPrivs.nonEmpty) rating = debugPrivs.size * 2

    /**
      * MAKE PRETTY PRINT FINDINGS
      */

    return rating
  } // END checkPrivs()

  /** MAP can contain multiple keys idiot. Check code that generated this. */
  /*
  private[this] def checkRegPersistence(vec: Vector[RegPersistenceInfo]): Int = {

    var riskRating = 0

    val vecPersistMap: Vector[mutable.Map[String, Int]] = for(value <- vec) yield value.persistenceMap
    /** Run keys greater than 0 */
    val filterZeroMap: Vector[mutable.Map[String, Int]] = for{
      value <- vecPersistMap
      (key, result) <- value
      if result > 0
    } yield value

    if(filterZeroMap.nonEmpty) {
      println("Printing keys and values greater than 0 for debuging purposes:\n\n")
      for((key, value) <- filterZeroMap) println(key + " -> " + value)
    } // END if

    /** Searching for memory leaks. Run keys greater than 0 */
    val memoryLeak: Vector[String] = for{
      regMap <- filterZeroMap
      (key, value) <- regMap
      if value > 5
    } yield key

    if (memoryLeak.nonEmpty) riskRating = riskRating + 100
    if (memoryLeak.nonEmpty) {
      println("A memory leak allowing an attacker to maintain persistence was found for the following pids: " +
        memoryLeak.mkString(", ") + "\nIt is extremely likely that your computer was compromised.\n")
    }

    /**
      * MAKE PRETTY PRINT FINDINGS
      */

    return riskRating
  } // END checkRegPersistence()

  private[this] def regPersistCheck(map: mutable.Map[String, Int]) = {

    val key = map.k

  } // END regPersistCheck()
*/
  /** Check for unlinked DLLs */
  private[this] def checkLdr(vec: Vector[LdrInfo]): Int = {
    var riskRating = 0
    /*
    pid: String,
    baseLoc: Vector[String],   // base location of DLL.
    probs: Vector[String],     // Finds lines that indicate there's an unlinked DLL.
    dllName: Vector[String],
    pathDiscrepancies: Boolean = false
    */

    /**
      * THIS IS PROBABLY A PROBLEM
      */

    val probsVec: Vector[Vector[String]] = for (value <- vec) yield value.probs

    val unlinked = for {
      value <- vec
      if value.probs.nonEmpty
    } yield (value.pid, value.probs.mkString("\n"), value.probs.size)

    if (unlinked.nonEmpty) {
      println("\nThe following unlinked DLLs were discovered: \n")
      for {
        (key, value, size) <- unlinked
      } println("PID: " + key + "\nNumber of unlinked DLLs: " + size.toString + "\nUnlinked DLLs: \n" + value)
    } // END if

    if (unlinked.nonEmpty) riskRating = unlinked.size * 10

    /**
      * MAKE PRETTY PRINT FINDINGS
      */

    return riskRating
  } // END checkLdr()
  private[this] def checkRemoteMapped(vec: Vector[(String, String)]): Int = {

    var riskRating = 0

    val remoteMappedSize = vec.size
    if (vec.nonEmpty) {
      println(remoteMappedSize.toString + " remote mapped drives were found on the system.")
      for ((key, value) <- vec) println("PID: " + key + " -> " + value)
    }
    if (remoteMappedSize > 2) riskRating = 20
    else if (remoteMappedSize <= 2) riskRating = 10
    else if (remoteMappedSize == 0) riskRating = 0

    /**
      * MAKE PRETTY PRINT FINDINGS
      */

    return riskRating
  } // END checkRemoteMapped()

  /**
    *
    * CHECK SHELLBAGS FOR TIMESTOMPING (303)
    * LOOK AT LAST UPDATE!!
    *
    */

  private[this] def checkShimCacheTime(vec: Vector[ShimCache]): (Int, Vector[ShimCache]) = {

    var riskRating = 0

    // val years = vec.map(x => ShimCache(x.lastMod, x.lastUpdate.take(4), x.path))
    /** Look for dates later than 2017. */
    val timeStomp = for{
      value <- vec
      if Try(value.lastUpdate.take(4).toInt).getOrElse(0) > 2017
    } yield value

    /** Look for dates less than 1995 */
    val timeStompEarly = for{
      value <- vec
      if Try(value.lastUpdate.take(4).toInt).getOrElse(3418) < 2000
    } yield value

    if(timeStomp.nonEmpty || timeStompEarly.nonEmpty) {
      println("\nTimestomping was found on the system indicating that the system was breached\n")
      println("Examine the following entries:\n")
      riskRating = 100
      if(timeStomp.nonEmpty) timeStomp.foreach(println)
      if(timeStompEarly.nonEmpty) timeStompEarly.foreach(println)
    }
    val concatShells = timeStomp ++: timeStompEarly

    return (riskRating, concatShells)
  } // END checkShimCacheTime()

  private[this] def checkRootKitResults(root: RootkitResults) = {


    /**
      * MAKE PRETTY PRINT FINDINGS
      */

  } // END checkRootkitResults

  private[this] def checkRegistry(root: (Vector[String], Vector[String])) = {


  } // END checkRegistry()

  private[this] def checkSysState(sys: SysState): Int = {
    var riskRating = 0

    /** Services that were stopped that indicate there is a problem.. */
    val svcStopped: Vector[String] = sys.svcStopped

    // ("Wscsvc", "Wuauserv", "BITS", "WinDefend", "WerSvc")

    /** Rating depends on which service was stopped. WinDefend might be disabled by AV */
    if (svcStopped.nonEmpty) {
      if (svcStopped.contains("WinDefend")) {
        println("Windows defender was disabled. This might be OK if you use other anti-virus software.\n\n")
        riskRating = 5
      } // END if
      if (svcStopped.contains("BITS")) {
        println("Background Intelligent Transfer Service was disabled. This might have been done by malware.\n\n")
        riskRating = riskRating + 20
      } // END if
      if (svcStopped.contains("Wscsvc")){
        println("Wscsvc.dll is disabled. Wscsvc provides support for the Windows security service." +
        "If it is disabled, the user will not receive security alerts.\n\n")

        riskRating = riskRating + 100
      } // END if
      if (svcStopped.contains("Wuauserv")){
        println("Wuauserv is disabled. Wuauserv provides Windows updates. If the user did not disable this " +
        "on their own, it's likely that the system was breached.\n\n")
        // LOOK THIS UP
      }
    } // END if svcStopped.nonEmpty

    return riskRating
  } // END checkSysState()

  private[this] def checkYara(yaraObj: YaraBrain): Int = {

    /** Grab significant yara scan findings */
    val yarMalware: Vector[YaraParseString] = yaraObj.malware
    val yarSuspicious: YaraSuspicious = yaraObj.suspItems
    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs
    // val suspStrs: Vector[YaraParseString] = yarSuspicious.suspStrings

    val malwareRating = checkMalware(yarMalware)
    val antidebugRating = checkAntiDebug(antidebug)
    val exploitkitRating = checkExploitKits(exploitKits)
    val webshellsRating = checkWebshells(webshells)
    val malDocRating = checkMalDocs(malDocs)

    val riskRating = malwareRating + antidebugRating + exploitkitRating + webshellsRating + malDocRating

    return riskRating
  } // END checkYara()

  private[this] def checkMalware(vec: Vector[YaraParseString]): Int = {
    var riskRating = 0

    val checkMalwareCount = vec.size
    if (checkMalwareCount > 0) riskRating = checkMalwareCount * 10

    return riskRating
  } // END checkMalware()
  private[this] def checkAntiDebug(vec: Vector[YaraParse]): Int  = {
    var riskRating = 0

    val checkAntiDebug = vec.size * 5

    checkAntiDebug
  } // END checkMalware()
  private[this] def checkExploitKits(vec: Vector[YaraParse]): Int = {
    var riskRating = 0

    val exploitkitCount = vec.size * 10

    exploitkitCount
  } // END checkExploitKits()
  private[this] def checkWebshells(vec: Vector[YaraParse]): Int  = {
    var riskRating = 0

    val webShellCount = vec.size * 5

    webShellCount
  } // END checkWebShells()
  private[this] def checkMalDocs(vec: Vector[YaraParse]): Int  = {
    var riskRating = 0

    val malDocsCount = vec.size * 10

    malDocsCount
  } // END checkMalDocs()

  private[this] def checkPorts(yaraVec: Vector[YaraParseString], netVec: Vector[NetConnections]) = {
    /**
      * YaraParseString
      * pid: String,
      * srcIP: String,
      * destIP: String,
      * destLocal: Boolean = true,  // Is the destination IP address local?
      * vnc: Boolean
      */

      /** pid -> numbers found with yarascan that we might be able to match to a port number */
    val localYar: Vector[(String, String)] = yaraVec.map(x => (x.proc, x.str.replaceAll("\\.", "")))
    val destYar: Vector[(String, String)] = yaraVec.map(x => (x.proc, x.str.replaceAll("\\.", "")))
    val yarConcat = localYar ++: destYar

    val connDestPorts: Vector[(String, String)] = {
      netVec.map(x => (x.pid, Try(x.destIP.splitLast(':')(1)).getOrElse("").trim))
    }

    val connSrcPorts: Vector[(String, String)] = {
      netVec.map(x => (x.pid, Try(x.srcIP.splitLast(':')(1)).getOrElse("").trim))
    }

    val netConcat = connDestPorts ++: connSrcPorts
    // Need to filter to only include unique ports

    /** Both are Vector[Vector[String]] (0=pid, 1=port, 2=description)*/
    val (netFound, yarFound) = searchPorts(yarConcat, netConcat)

    netFound

  } // END checkPorts()

  /** Given an integer value based on findings that we'll use to determine system risk rating. */
  private[this] def riskValue(yarVec: Vector[String], netVec: Vector[String]): Int = {

    var riskNo = 0

    // After checking netVec, we need to remove ports that are in both yarVec and netVec

    return riskNo
  } // END riskValue()

  private[this] def searchPorts(yarVec: Vector[(String, String)], netVec: Vector[(String, String)]):
                                                        (Vector[Vector[String]], Vector[Vector[String]]) = {

    /** Vector[Vector(pid, portNo, Description)]*/
    val yarTargetsFound: Vector[Vector[String]] = for{
      tup <- yarVec
    } yield Vector(tup._1, tup._2, getCommonTargetPort(tup._1))

    val yarProbsFound: Vector[Vector[String]] = for{
      tup <- netVec
    } yield Vector(tup._1, tup._2, getPortRisk(tup._2))

    /** Filter out ports that did not match. */
    val filterYarTargets: Vector[Vector[String]] = yarTargetsFound.filterNot(x => x(2) == "None")
    val filterYarProbs: Vector[Vector[String]] = yarProbsFound.filterNot(x => x(2) == "None")

    return (filterYarTargets, filterYarProbs)
  } // END searchPorts

  private[this] def getCommonTargetPort(portNo: String): String = {

    // Check for the following ports
    val commonTargetPorts = Map("20" -> "ftp", "5060" -> "SIP", "554" -> "rtsp", "17185" -> "soundsvirtual",
      "3369" -> "satvid-datalnk", "1883" -> "IBM MQSeries Scada", "333" -> "Texas Security", "2080" -> "autodesk-nlm",
      "5432" -> "postgres database server", "4289" -> "VRLM Multi User System",
      "3377" -> "Cogsys Network License Manager", "47808" -> "bacnet", "4899" -> "Remote Administrator Default Port",
      "500" -> "VPN Key Exchange", "3366" -> "Creative Partner", "3339" -> "anet-l OMF data l",
      "563" -> "nntp over TLS protocol", "2003" -> "cfingerd GNU Finger", "3370" -> "satvid Video Data Link",
      "222" -> "Berkeley rshd with SPX auth", "3281" -> "sysopt", "3368" -> "satvid Video Data Link",
      "7070" -> "ARCP", "3421" -> "Bull Apprise Portmapper", "4500" -> "sae-urn",
      "16992" -> "Intel AMT remote managment", "5800" -> "VNC", "3277" -> "awg proxy",
      "502" -> "asl-appl-proto", "212" -> "SCIENTA-SSDB", "3378" -> "WSICOPY", "3459" -> "Eclipse 2000 Trojan",
      "3328" -> "Eaglepoint License Manager", "5984" -> "couchdb", "3360" -> "kv-server", "3348" -> "Pangolin Laser",
      "3052" -> "APCPCNS", "3343" -> "MS Cluster Net", "44444" -> "Prosiak Trojan", "3286" -> "E-Net",
      "22222" -> "Donald Dick Trojan", "3353" -> "fatpipe", "3355" -> "Ordinox Database", "513" -> "Grlogin Trojan"
    )

    /** Need to make sure this returns something if not found. */
    return Try(commonTargetPorts(portNo)).getOrElse("None")
  } // END getCommonTargetPort()

  /** Pass a port number to check risk associated w/ port number */
  private[this] def getPortRisk(portNo: String): String = {

    /** Map of ports commonly used by hackers. List should include more ports.
      * Values based on SANS port report https://isc.sans.edu/port
      */
    val probPorts = TreeMap[String, String]("4946" -> "high", "4344" -> "medium", "4331" -> "medium", "2525" -> "high",
      "513" -> "critical", "2087" -> "medium", "5060" -> "high", "1234" -> "high", "3097" -> "medium",
      "30000" -> "critical", "54321" -> "critical", "33333" -> "critical", "5800" -> "medium", "3459" -> "critical",
      "44444" -> "critical", "22222" -> "critical", "491" -> "medium",
      "3575" -> "critical", "3573" -> "high", "3569" -> "high", "3566" -> "critical", "3558" -> "high",
      "3552" -> "high", "3551" -> "high", "3545" -> "high", "3509" -> "high", "3074" -> "low", "2702" -> "critical",
      "2120" -> "medium", "1656" -> "low", "1613" -> "critical", "655" -> "medium", "3074" -> "low",
      "1749" -> "medium", "2120" -> "low", "2273" -> "low", "3558" -> "high", "3571" -> "high", "4344" -> "low",
      "4946" -> "medium", "5355" -> "critical", "5827" -> "low", "6882" -> "medium", "6957" -> "low", "7834" -> "low",
      "9343" -> "low", "10034" -> "low", "10070" -> "critical", "11460" -> "low", "10550" -> "low", "11786" -> "low",
      "11868" -> "low", "12632" -> "low", "13600" -> "low", "14427" -> "low", "14501" -> "medium", "14502" -> "medium",
      "14503" -> "medium", "14504" -> "medium", "14506" -> "medium", "14518" -> "medium", "14519" -> "medium",
      "14546" -> "medium", "14547" -> "medium", "14559" -> "medium", "14562" -> "medium", "14576" -> "medium",
      "14580" -> "medium", "14581" -> "medium", "14582" -> "medium", "14585" -> "low", "14814"  -> "low",
      "14955" -> "medium", "15714" -> "low", "16183" -> "low","17225" -> "low", "17500" -> "critical",
      "17730" -> "medium", "18170" -> "low", "19120" -> "low", "19451" -> "low", "19820" -> "low", "19948" -> "low",
      "19999" -> "low", "20012"  -> "low", "20707" -> "low", "21027" -> "critical", "21646" -> "low", "21715" -> "low",
      "22238" -> "low", "22328" -> "low", "24404" -> "low", "24542" -> "low", "24863" -> "low", "25441" -> "low",
      "26431" -> "low", "26858" -> "low", "27719" -> "low", "27745" -> "low", "27969" -> "low", "28607" -> "low",
      "29294" -> "low", "29440" -> "high", "30516" -> "low", "31101" -> "high", "31695" -> "low", "31949" -> "low",
      "32172" -> "low", "32414" -> "critical", "33063" -> "low", "33120" -> "low", "33331" -> "low", "33978" -> "low",
      "34425" -> "low", "34518" -> "low", "34751" -> "low", "34885" -> "low", "35166" -> "low", "35366" -> "low",
      "35393" -> "low", "35899" -> "low", "35902" -> "low", "36123" -> "critical", "36138" -> "low", "36181" -> "low",
      "36289" -> "medium", "36538" -> "medium", "36620" -> "high", "36787" -> "low", "36817" -> "low", "37087" -> "low",
      "37558" -> "low", "38250" -> "low", "38418" -> "low", "38610" -> "low", "38857" -> "low", "38972" -> "medium",
      "38979" -> "low", "38972" -> "medium", "38982" -> "medium", "39203" -> "low", "39395" -> "medium",
      "39571" -> "low", "39804" -> "medium", "40089" -> "low", "40297" -> "low", "40400" -> "low", "40483" -> "low",
      "40778" -> "low", "40902" -> "low", "41712" -> "low", "41995" -> "medium", "42193" -> "low", "42866" -> "medium",
      "43312" -> "medium", "43884" -> "low", "45827" -> "low", "45977" -> "low", "46573" -> "medium",
      "47123" -> "medium", "47554" -> "low", "48392" -> "low", "49387" -> "low", "49438" -> "medium",
      "49491" -> "low", "49792" -> "low", "50076" -> "low", "50086" -> "low", "50088" -> "medium", "51533" -> "high",
      "51799" -> "low", "52622" -> "low", "52656" -> "high", "53773" -> "low", "54191" -> "low", "54256" -> "critical",
      "54373" -> "low", "55733" -> "medium", "56168" -> "low", "57325" -> "low", "57621" -> "critical",
      "57925" -> "medium", "58067" -> "low", "58085" -> "low", "58180" -> "low", "58231" -> "high", "58554" -> "low",
      "58558" -> "medium", "58582" -> "low", "58838" -> "low", "58842" -> "low", "58975" -> "low", "59107" -> "medium",
      "59134" -> "low", "49141" -> "low", "59163" -> "low", "59206" -> "medium", "59566" -> "low", "59707" -> "high",
      "59789" -> "low", "59873" -> "low", "59912" -> "medium", "60527" -> "low", "61134" -> "medium", "61905" -> "high",
      "62581" -> "low", "63656" -> "low", "63747" -> "low", "63800" -> "medium", "63867" -> "medium", "64076" -> "low",
      "64549" -> "medium", "65285" -> "low", "350" -> "low", "577" -> "low", "857" -> "low",
    ) // END probPorts treemap

    return Try(probPorts(portNo)).getOrElse("None")
  } // END getProbPort()


} // END FindSuspiciousProcesses object
