package com.bbs.vol.windows

/**
  * @ J. Alexander
  * @version 1.0
  *
  *          Contains main method of program.
  */

import scala.io.Source
import sys.process._
import java.io.File
import java.util.Calendar
import com.bbs.vol.processtree._
import scala.collection.immutable.TreeMap

object VolatilityIDS {
  def main( args: Array[String] ): Unit = {

    // Need to read in user input from a config file.

    val (os, memFile) = parseConfig()

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
    val dumpDir = mkDir( os )

    val discovery = new VolDiscoveryWindows( memFile, os, dumpDir )

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
    val discoveryResult: Discovery = discovery.run()

    val process: Vector[ProcessBbs] = discoveryResult.proc._1
    val netConns = discoveryResult.net._1

    val processDiscovery = new ProcessDiscoveryWindows(os, memFile, process, netConns)
    val procDiscoveryResult: ProcessBrain = processDiscovery.run

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
        "\nThe configuration file was successfully read...\n\nRunning the program...\n\n" )
    }  else System.exit( 1 )

    return (cleanSplit(1), cleanSplit(3))
  } // END parseConfig()

  /** Creates a directory where we'll store log, prefetch, and pcap info in txt files */
  private[windows] def mkDir(os: String): String = {
    val cal = Calendar.getInstance()
    val date = {
      cal.get(Calendar.MONTH) + "-" + cal.get(Calendar.DATE) + "_" + cal.get(Calendar.HOUR) + cal.get(Calendar.MINUTE)
    }
    val dirName = System.getProperty("user.dir") + "/" + os + date
    val dir = new File(dirName)
    // val checkCreation: Boolean = dir.mkdir()

    if(dir.mkdir()){
      println(s"\n\nLog files, prefetch files, mft, and pcaps will be located in the following directory:\n$dirName\n\n")
    } else{
      println("\n\n\nWe failed to create a directory for lots of helpful information. Check and make sure\n" +
        s"the directory $dirName doesn't already exist.\n\n")
    }
    val shortDirName = os + date
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
      s">> python vol.py $memFile imageinfo\n\n" )

    val imageInfo: Option[String] = Some( s"python vol.py -f $memFile imageinfo".!!.trim )

    print(imageInfo.getOrElse(""))
  }

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
    "NC.EXE" -> "Netcat listener. Commonly used by hackers to create backdoors. Also used by advanced computer users for sharing files and other tasks.",
    "NAVAPSVC.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "NVSRVC32.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "NAVAPW32.EXE" -> "These are Symantec’s North AnvtiVirus processes. They or whatever virus program you use should run all the time.",
    "REALSCHED.EXE" -> "RealNetworks Scheduler is not an essential process. It checks for updates for RealNetworks products. It can be safely disabled.",
    "RUNDLL32.EXE" -> "A system process that executes DLLs and loads their libraries.",
    "SAVSCAN.EXE" -> "Nortons AntiVirus process.",
    "SERVICES.EXE" -> "An essential process that manages the starting and stopping of services including the those in boot up and shut down. Do not terminate it.",
    "SMSS.EXE" -> " Session Manager SubSystem is a system process that is a central part of the Windows operating system.",
    "SPOOLSV.EXE" -> " Microsoft printer spooler service handles local printer processes. It’s a system file.",
    "SVCHOST.EXE" -> " You may have more than six appearances of this process or less. It’s there multiple times to handle processes executed from DLLs. Leave it there.",
    "SYSTEM" -> " This is a file that stores information related to local hardware settings in the registry under ‘HKEY_LOCAL_MACHINE’. Kill it and kiss your PC’s stability bye bye.",
    "SYSTEM IDELE PROCESS" -> " calculates the amount of CPU currently in use by applications. This won’t go away no matter how hard you try. Don’t try it, OK?",
    "TASKMGR.EXE" -> " Appears when you press Ctrl+Alt+Del.",
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
    if (6585 until 6682 contains value) result = ProcAUBR.get()
    if (6683 until 6773 contains value) result = ProcBSCI.get()
    if (6774 until 6778 contains value) result = ProcCJCN.get()
    if (6779 until 6787 contains value) result = ProcCOCW.get()
    if (6787 until 6875 contains value) result = ProcCXDK.get()
    if (6876 until 6973 contains value)  result = ProcDLEI.get()
     if (6974 until 7072 contains value) result = ProcEJFH.get()
     if (7073 until 7279 contains value) result = ProcFIHO.get()
     if (7280 until 7367 contains value) result = ProcHPIC.get()
     if (7368 until 7378 contains value) result = ProcIDIN.get()
     if (7379 until 7576 contains value) result = ProcIOKL.get()
     if (7577 until 7676 contains value) result = ProcKMLL.get()
     if (7677 until 7766 contains value) result = ProcLMMB.get()
     if (7767 until 7775 contains value) result = ProcMCMK.get()
     if (7776 until 7788 contains value) result = ProcMLMX.get()
     if (7789 until 7880 contains value) result = ProcMYNP.get()
     if (7881 until 7982 contains value) result = ProcNQOR.get()
     if (7983 until 8070 contains value) result = ProcOSPF.get()
     if (8071 until 8082 contains value) result = ProcPGPR.get()
     if (8083 until 8265 contains value) result = ProcPRRA.get()
     if (8266 until 8280 contains value) result = ProcRBRP.get()
     if (8281 until 8367 contains value) result = ProcRRSC.get()
     if (8368 until 8375 contains value) result = ProcSDSK.get()
     if (8376 until 8383 contains value) result = ProcSLSS.get()
     if (8384 until 8466 contains value) result = ProcSTTB.get()
     if (8467 until 8483 contains value) result = ProcTCTS.get()
     if (8484 until 8667 contains value) result = ProcTTVC.get()
     if (8668 until 8766 contains value) result = ProcVDWB.get()
     if (8767 until 8782 contains value) result = ProcWCWR.get()
     if (8783 until 9090 contains value) result = ProcWSZZ.get()

    return result
  } // END matchProcess()

} // END ProcessDescription object


/** Contains info that will help determine which info to print in report and the risk the system faces. */
final case class RiskRating(riskRating: Integer)

/** Class looks at the results of previous scans and determines if indicators of a breach were found. */
object FindSuspiciousProcesses{

  def run(disc: Discovery, process: ProcessBrain) = {

    /** */
    var riskRating = 0

    /**
      * Get info from Discovery case class
      */

    val proc: Vector[ProcessBbs] = disc.proc._1
    /** callbacks, hiddenModules, timers, deviceTree, orphanThread, found */
    val rootkit: RootkitResults = disc.rootkit
    /** (pid -> Remote Mapped Drive) */
    val remoteMapped: Vector[(String, String)] = disc.remoteMapped
    /** Vector[String], Vector[String] */
    val (userReg, sysReg) = disc.registry
    /** svcStopped, suspCmds */
    val sysSt: SysState = disc.sysState

    /**
      * Get info from ProcessBrain
      */
    /** Need  */
    val yaraObj: YaraBrain = process.yara
    val regPersist: Vector[RegPersistenceInfo] = process.regPersistence
    val ldr: Vector[LdrInfo] = process.ldrInfo
    val privs: Vector[Privileges] = process.privs
    val yarSuspicious: YaraSuspicious = yaraObj.suspItems

    /** Grab significant yara scan findings */
    val yarMalware: Vector[YaraParseString] = yaraObj.malware
    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs
    val suspStrs: Vector[YaraParseString] = yarSuspicious.suspStrings

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

  } // END run()

} // END FindSuspiciousProcesses object
