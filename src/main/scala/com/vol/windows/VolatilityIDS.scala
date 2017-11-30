package com.bbs.vol.windows

/**
  * @ J. Alexander
  * @version 1.0
  *
  *          Contains main method of program.
  */

/**
  * TO DO
  * ** Create BBS_Reports directory and place all results inside directory inside for each scan.
  * ** Look for commonly changed fileNames (e.g. svchost.exe)
  * ** No DLLs showing up on Server 2003 Domain controller.
  * ** Connections scan was never fixed!
  * ** 127.0.0.1 is not external IP address.
  * ** Try running all scans right away and passing results as argument so we can use multi-threading.
  * ** Look for malfind that begins w/ MZ
  * ** What should be the parent of what?
  * ** Look for which processes are descended from cmd.exe and/or powershell.
  * ** Add missing common process and dll (crypt32.dll)
  * ** Ignore certain executables when considering risk of hidden DLLs (services, smss.exe)
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
import com.bbs.vol.utils.FileFun

import scala.collection.immutable.TreeMap
import com.bbs.vol.windows.StringOperations._

import scala.collection.mutable
import scala.collection.mutable.ArrayBuffer
import scala.util.Try

final case class Configuration(memFile: String,
                               os: String,
                               kdbg: String,
                               dump: Boolean,
                               yara1: String = "",
                               yara2: String = "",
                               yara3: String = "",
                               yara4: String = "",
                               verbose: Boolean = false)

object VolatilityIDS extends FileFun {
  /*****************************************************
    ****************************************************
    ******************~~~~~MAIN~~~~*********************
    ****************************************************
    ****************************************************/
  def main( args: Array[String] ): Unit = {

    // Need to read in user input from a config file.

    /** Read and parse the config file. */
    val config: Configuration = parseConfig()

    val memFile: String = config.memFile
    val os: String = config.os
    val kdbg: String = config.kdbg
    val yaraVec: Vector[String] = Vector(config.yara1, config.yara2,config.yara3, config.yara4)

    /** Boolean that tells us if we should automatically dump suspicious processes from memory. Not coded yet. */
    val dump: Boolean = config.dump

    /** A vector of rules we can pass to yara for the user. */
    val userYaraRules = yaraVec.filter(x => x.nonEmpty)

    if(kdbg.nonEmpty){
      val cwd = System.getProperty("user.dir")
      writeToFile(cwd + "user_config.txt", s"[DEFAULT]\nPROFILE=$os\nLOCATION=file:///$cwd\nKDBG=$kdbg")
    }
    /**
      * Check and make sure valid file extension
      */

    val fileBool: (Boolean, String) = checkDir( memFile )

    /** Check and make sure the memory file is valid */
    if (fileBool._1) {

    }else{
      println( "The memory file you entered does not exist.\n\n" +
        s"Check and make sure ${fileBool._2} is the correct file name.\n\nExiting program..." )
      System.exit( 1 )
    }


    /** Make a directory to store log, prefetch, and pcap output as txt by volatility */
    val dumpDir = mkDir( memFile )

    /** Broadly examine image for malicious behavior. */
    val discoveryResult: Discovery = VolDiscoveryWindows.run( memFile, os, kdbg, dumpDir )

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
    val processDiscovery = ProcessDiscoveryWindows.run(memFile, os, kdbg, process, netConns)

    /** Search for hidden executables. */
    // val hiddenExecs = findHiddenExecs(process)

    /** Determine overall risk rating for memory image */
    val riskRating = 0 // FindSuspiciousProcesses.run(discoveryResult, processDiscovery)

    /** Need to write extract parts of Discovery (proc), and pass it to next section of program. */

    /** Write report */
    CreateReport.run(memFile, os, processDiscovery, discoveryResult, riskRating)

    println("\n\nReport written successfully...\n\n")
    /** Do scans not included w/ report and send to file. */

    // envars
    // extra yara scans

    /** Move the files that were written to volatility directory into another file. */

    // CleanUp.run()

  } // END main()

  /****************************************************************************************/
  /***************************************** END main() ***********************************/
  /****************************************************************************************/

  /** Parses the config file. */
  private[this] def parseConfig( ): Configuration = {

    val fileName = System.getProperty("user.dir") + "/" + "bbs_config.txt"
    val readConfig: Vector[String] = readFileTransform(fileName)(y => y.filterNot(x => x.contains("#")))
    /*
    val src = Source.fromFile( fileName )
    val readConfig = src.getLines.filterNot( _.contains( "#" ) )
      .toVector
    src.close
    */

    val splitUp: Vector[Array[String]] = readConfig.map(_.split("~>"))


    val os = if (Try(splitUp(0)(0).trim.toLowerCase()).getOrElse("") == "profile") {
      if (Try(splitUp(0)(1).trim).getOrElse("").nonEmpty) {
        splitUp(0)(1).trim
      } else {
          ""
      }
    } else "" // memFile

    val memFile = if (Try(splitUp(1)(0).trim.toLowerCase()).getOrElse("")  == "memoryfilename") {
      if (Try(splitUp(1)(1).trim).getOrElse("").nonEmpty) {
        splitUp(1)(1).trim
      } else {
        ""
      }
    } else ""// memFile

    val kdbg: String = if (Try(splitUp(2)(0).trim.toLowerCase()).getOrElse("")  == "kdbg") {
        Try(splitUp(2)(1).trim).getOrElse("")
      } else {
        ""
      } // kdbg()

    var dump = if (Try(splitUp(3)(0).trim.toLowerCase()).getOrElse("")  == "dump") {
      if (splitUp(3)(1).toLowerCase() == "true") {
        true
      } else {
        false
      }
    } else false

    dump = if (Try(splitUp(2)(0).trim.toLowerCase()).getOrElse("")  == "dump") {
      if (splitUp(2)(1).toLowerCase() == "true") {
        true
      } else {
        false
      }
    } else false // dump

    val yaraRule1: String = if (Try(splitUp(3)(0).trim.toLowerCase()).getOrElse("")  == "rules1") {
        Try(splitUp(3)(1).trim).getOrElse("")
    } else if (Try(splitUp(2)(0).trim.toLowerCase()).getOrElse("")  == "rules1") {
        Try(splitUp(2)(1).trim).getOrElse("")
    } else if (Try(splitUp(4)(0).trim.toLowerCase()).getOrElse("")  == "rules1") {
        Try(splitUp(4)(1).trim).getOrElse("")
    } else {
      ""
    } // yaraRule1

    val yaraRule2: String = if (Try(splitUp(3)(0).trim.toLowerCase()).getOrElse("")  == "rules2") {
      Try(splitUp(3)(1).trim).getOrElse("")
    } else if (Try(splitUp(4)(0).trim.toLowerCase()).getOrElse("")  == "rules2") {
      Try(splitUp(4)(1).trim).getOrElse("")
    } else if (Try(splitUp(5)(0).trim.toLowerCase()).getOrElse("")  == "rules2") {
      Try(splitUp(5)(1).trim).getOrElse("")
    } else {
      ""
    } // yaraRule1

    val yaraRule3: String = if (Try(splitUp(4)(0).trim.toLowerCase()).getOrElse("")  == "rules3") {
      Try(splitUp(4)(1).trim).getOrElse("")
    } else if (Try(splitUp(5)(0).trim.toLowerCase()).getOrElse("")  == "rules3") {
      Try(splitUp(5)(1).trim).getOrElse("")
    } else if (Try(splitUp(6)(0).trim.toLowerCase()).getOrElse("")  == "rules3") {
      Try(splitUp(6)(1).trim).getOrElse("")
    }else if(Try(splitUp(7)(0).trim.toLowerCase()).getOrElse("")  == "rules3"){
      Try(splitUp(7)(1).trim).getOrElse("")
    }
    else {
      ""
    } // yaraRule1
    val yaraRule4: String = if (Try(splitUp(5)(0).trim.toLowerCase()).getOrElse("")  == "rules4") {
      Try(splitUp(5)(1).trim).getOrElse("")
    } else if (Try(splitUp(6)(0).trim.toLowerCase()).getOrElse("") == "rules4") {
      Try(splitUp(6)(1).trim).getOrElse("")
    } else if (Try(splitUp(7)(0).trim.toLowerCase()).getOrElse("") == "rules4") {
      Try(splitUp(7)(1).trim).getOrElse("")
    }else if(Try(splitUp(8)(0).trim.toLowerCase()).getOrElse("")  == "rules4"){
      Try(splitUp(8)(1).trim).getOrElse("")
    }
    else {
      ""
    } // yaraRule1

    val projectName = if(Try(splitUp(3)(0).trim.toLowerCase()).getOrElse("") == "projectname") {
        Try(splitUp(3)(1).trim).getOrElse("")
      } else if (Try(splitUp(2)(0).trim.toLowerCase()).getOrElse("")  == "projectname") {
      Try(splitUp(2)(1).trim).getOrElse("")
        } else if (Try(splitUp(4)(0).trim.toLowerCase()).getOrElse("")  == "projectname") {
      Try(splitUp(4)(1).trim).getOrElse("")
    } else if (Try(splitUp(5)(0).trim.toLowerCase()).getOrElse("")  == "projectname") {
      Try(splitUp(5)(1).trim).getOrElse("")
    } else if (Try(splitUp(6)(0).trim.toLowerCase()).getOrElse("")  == "projectname") {
      Try(splitUp(6)(1).trim).getOrElse("")
    }else if(Try(splitUp(7)(0).trim.toLowerCase()).getOrElse("")  == "projectname"){
      Try(splitUp(7)(1).trim).getOrElse("")
    }else if (Try(splitUp(8)(0).trim.toLowerCase()).getOrElse("")  == "projectname") {
      Try(splitUp(8)(1).trim).getOrElse("")
    }else if(Try(splitUp(9)(0).trim.toLowerCase()).getOrElse("")  == "projectname"){
      Try(splitUp(9)(1).trim).getOrElse("")
    }else{
      ""
    }

    if ( memFile.nonEmpty && os.nonEmpty ) {
      println( "\n\nWelcome to the Big Brain Security Volatile IDS! \n" +
        "\nThe configuration file was successfully read...\n\nRunning the program..." )
    }  else {
      println("The program could not find a profile or memory file name in bbs_config.txt.")
      println("Please update the bbs_config.txt file in your volatility directory.")
      println("Exiting program...\n")
      System.exit( 1 )
    }

    return Configuration(memFile, os, kdbg, dump, yaraRule1, yaraRule2, yaraRule3, yaraRule4)
  } // END parseConfig()
/*
  /**
    * Find Kdbg offset
    *
    * Need to run kdbg only if the value isn't input in config file.
    */
  private[windows] def findKdbg(memFile: String, os: String): String = {

    val strBuilder = new StringBuilder()
    /** Need to grab kdbg block to deal with LOTS OF BUGS!!! */
    val kdbg: String = Seq("python","vol.py", "-f", memFile, s"--profile=$os", "kdbgscan").!!.trim


    println("printing stream as test.\n")

    kdbg.foreach(println)
    val kdbgStr = kdbg.toString

    println("Printing kdbgStr\n" + kdbgStr)
    val kdbgVec = Source.fromString(kdbgStr).getLines.toVector

    /** Split on the different outputs */
    val splitOnKdbg: Vector[Array[String]] = {
      kdbgVec.map(x => x.split("""\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*"""))
    }

    println("Printing splitOnKdbg")
    splitOnKdbg.foreach(println)

    /** Split on name */
    val splitOnName: Vector[Array[String]] = kdbgVec.map( x => x.split("""KDBGHeader""") )
    // Now we need to find the following offset


    println("Printing splitOnName:")
    for{
      value <- splitOnName
      row <- value
    }println(row)

    val memLocOffset = "0x".r
    /** Since we need the profile to line up, we use Win or Vista. Win almost always works. */
    val osReg = "(Win|VistaSP).+".r

    /** Get Vector[Array[memLocations]] */
    val memLoc: Vector[String] = for{
      value <- splitOnKdbg
      line <- value
    } yield memLocOffset.findFirstIn(line).getOrElse("Failed")

    println("printing memLoc")
    for{
      value <- memLoc
    } println(value)


    val profileName: Vector[String] = for{
      value <- splitOnName
      line <- value
    } yield osReg.findFirstIn(line).getOrElse("FAILED")

    println("printing profileName")
    for{
      value <- memLoc
    } println(value)

    /** Buffer to store offsets that match up */
    var buff = ArrayBuffer[String]()

    var i = 0
    while(i < memLoc.length){
      /** This won't line up. */
      if(profileName(i) == memFile) buff + memLoc(i)

      i = i + 1
    } // END while
    println("Printing buff as a test...\n\n")
    buff.foreach(println)

    /** In case there are multiple matches, we want to find the most common value. */
    val mostCommonMemLoc: String = buff.filterNot(_.equals("Failed")).groupBy(identity).maxBy(_._2.length)._2(0)

    println(s"\n\nDetermined that the kdbg block is $mostCommonMemLoc. If the program has run, you might need to determine" +
      s"the kdbg block manually and set it in the config file.\n\n")

    mostCommonMemLoc

    // findFirstIn for each to get memLocs

    // Then we need to split on "KDBGHeader" and then from index(1) grab the word that starts with Win


    /** Going to worry about this code later. */
    /*
    import scala.sys.process.{Process, ProcessLogger}

    var (iiOut, iiErr) = ("", "")  // for collecting Process output
    val getii = Process(s"python vol.py -f $memFile imageinfo")
      .run(ProcessLogger(iiOut += _, iiErr += _))


    // . . .
    // do other useful stuff
    // or set a timeout alarm and wait for it
    // . . .

    val imageInfo: Option[String] =
      if (getii.isAlive()) {
        // report failure
        getii.destroy()
        Some(iiOut.trim)
      } else if (getii.exitValue() != 0 || iiErr != "") {
        // report failure
        None
      } else
        Some(iiOut.trim)
*/
  } // END findKdbg()

  */
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
/*
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
*/


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

} // END ProcessDescription object

/** Contains info that will help determine which info to print in report and the risk the system faces. */
final case class RiskRating(riskRating: Integer)

/** Class looks at the results of previous scans and determines if indicators of a breach were found. */
object FindSuspiciousProcesses {

  def run(disc: Discovery, process: ProcessBrain): Int = {

    /**
      * MISSING:
      * Rootkit Analysis
      * Find Hidden Execs
      */

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
    // val registry = disc.registry
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
    // val (shimRisk, shimCacheTime): (Int, Vector[ShimCache]) = checkShimCacheTime(shim)
    // iskRating = riskRating + shimRisk
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
/*
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
*/
  private[this] def checkRootKitResults(root: RootkitResults) = {


    /**
      * MAKE PRETTY PRINT FINDINGS
      */

  } // END checkRootkitResults

  private[this] def checkRegistry(vec: Vector[RegPersistenceInfo]) = {

    var riskRating = 0
    var reportStr = ""
    val regHandles: Vector[RegistryHandles] = vec.map(x => x.handles)

    val count: Vector[(String, Int)] = regHandles.map(x => (x.pid, x.runCount))
    val filterCount = count.filter(_._2 > 3)

    if (filterCount.nonEmpty){
      reportStr = "\n\tDuplicate run keys are an indication that an attacker used the registry to establish persistence.\n"
      for(values <- filterCount) println(s"\t${values._2} links to the run key were found in PID: ${values._1}")
      if(filterCount.exists(x => x._2 > 8)) {
        println(s"\n\n\tWe have determined that an attacker used the run key to establish registry persistence.\n")
        riskRating = 100
      }
      else riskRating = 50
    }

  } // END checkRegistry()

  private[this] def checkSysState(sys: SysState): Int = {
    var riskRating = 0

    /** Services that were stopped that indicate there is a problem.. */
    val svcStopped = sys.svcStopped

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

object ExtraScans {

  private[this] def sysRegistryCheckXP(memFile: String, os: String, kdbg: String): Vector[String] = {

    val key1 =  "\"Microsoft\\Windows\\CurrentVersion\\RunOnce\""
    val key2 = "\"Microsoft\\Windows\\CurrentVersion\\Run\""
    val key3 = "\"SYSTEM\\CurrentControlSet\\Control\\" + "Session Manager\\" + "Memory Management\\" + "PrefetchParameters\""

    var runOnce = ""
    var run = ""
    var prefetch = ""

    if(kdbg.nonEmpty){
      runOnce = Try(s"python vol.py -f $memFile --profile=$os printkey -g $kdbg -K $key1".!!.trim ).getOrElse("")
      run =Try(s"python vol.py -f $memFile --profile=$os printkey -g $kdbg -K $key2".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py -f $memFile --profile=$os printkey -g $kdbg -K $key3".!!.trim ).getOrElse("")
    } else{
      runOnce = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key1".!!.trim ).getOrElse("")
      run = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key2".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key3".!!.trim ).getOrElse("")
    } // END if/else

    return Vector(runOnce, run, prefetch)
  }
  private[this] def userRegistryCheckXP(memFile: String, os: String, kdbg: String): Vector[String] = {
    val quote = "\""

    val key1 =  "\"HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\RunOnce\""
    val key2 = "\"HKEY_CURRENT_USER\\Software\\Microsoft\\CurrentVersion\\Run\""

    var runOnce = ""
    var run = ""

    if(kdbg.nonEmpty){
      runOnce = Try(s"python --conf-file=user_config.txt printkey -g $kdbg -K $key1".!!.trim ).getOrElse("")
      run =Try(s"python vol.py --conf-file=user_config.txt printkey -g $kdbg -K $key2".!!.trim ).getOrElse("")
    } else{
      runOnce = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key1".!!.trim ).getOrElse("")
      run = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key2".!!.trim ).getOrElse("")
    } // END if/else

    return Vector(run, runOnce)
  } // END userRegistryCheckXP()

  def extraExtras(memFile: String, os: String) = {

    // Run mandiant redline against memory dump also.

    /** Filename for timeliner */
    val timelinerName = memFile + "_timeliner.txt"

    val batch1 = "mactime -b timeliner2.txt -d > .csv"
    val timeliner = s"python vol.py --conf-file=user_config.txt timeliner --output=body --output-file=$timelinerName"

    val dumpRegistry = "python vol.py --conf-file=user_config.txt dumpregistry --dump-dir ./registry_dump.txt"

    val autoruns = "python vol.py --conf-file=user_config.txt autoruns -v"

    val hollowfind = "python vol.py --conf-file=user_config.txt hollowfind"

    /** Create memory dump based on hyberfil.sys */
    val createImage = "python vol.py imagecopy -f hiberfil.sys -O newimage.img"

    batch1
  } // END extraExtras()

  /***********************
    * Post report scans.
    **********************/

  /**
    *  This method throws a broken pipe exception. Probably a dependency issue.
    */
  private[this] def deviceTreeScan(memFile: String, os: String, kdbg: String): String = {

    /** We want to look at network, keyboard, and disk drivers (389) Also look for unnamed devices */
    var deviceTree = ""
    if(kdbg.nonEmpty){
      deviceTree = {
        Try( s"python vol.py --conf-file=user_config.txt devicetree".!!.trim )
          .getOrElse("There was an error while reading devicetree scan...")
      }
    }else{
      deviceTree = {
        Try( s"python vol.py -f $memFile --profile=$os devicetree".!!.trim )
          .getOrElse("There was an error while reading devicetree scan...")
      }
    }

    return deviceTree
  } // END deviceTreeScan()

  /** Until I fully understand the output of envars module, I'm just going to return full output */
  private[this] def envScan(memFile: String, os: String, kdbg: String): String = {

    println("\n\nRunning envars scan...\n\n")

    /** environmental variables scan */
    var envars = ""
    if(kdbg.nonEmpty){
      envars = {
        Try( s"python --conf-file=user_config.txt envars".!!.trim ).getOrElse("")
      }
    }else {
      envars = {
        Try( s"python vol.py -f $memFile --profile=$os envars --silent".!!.trim ).getOrElse("")
      }
    }

    return envars

    /*
    /** WARNING: Check with actual output because we might not need to drop while "---" */

    /** Separate into lines to filter out unnecessary info and then turn it back into a string */
    val filtered: String = parseOutputDashEnv(envVars.getOrElse("")).mkString("\n")

    /** Creates a Vector with the information for each PID in each slot  */
    val splitEnvVars: Vector[String] = envVars.getOrElse("").split("\\*+").toVector

    /** first filter out USERNAME, USERDOMAIN, SESSIONNAME, USERPROFILE lines */
    val filteredEnv = splitEnvVars.filterNot(_.contains("USERNAME"))

    /** Use to pull out the PID */
    val lookaheadPID = """(?<=PID\s)\d+""".r

    /** Contains all the PIDs*/
    val pids: Vector[Option[String]] = splitEnvVars.map(x => lookaheadPID.findFirstIn(x))

    /** Use to pull out the PPID  */
    val lookaheadPPID = """(?<=PPID\s)\d+""".r

    /** Contains a Vector made up of PPIDs  */
    val ppids: Vector[Option[String]] = splitEnvVars.map(x => lookaheadPPID.findFirstIn(x))

    // For each section separated by **** we need Pid, PPid and variables.
    // it probably won't hurt to save other info like USERNAME & USERPROFILE.

    // For version 1.0 of this program, we'll suppress output of known variables with --silent (p. 230).
    // Eventually we might want to make this more robust because the envars module is super powerful.

    // envars module can be extremely helpful for determining which processes are infected (229)

*/
  } // END envScan()

  /**
    * Get the results of checking system registry keys sometimes indicative of persistence
    *
    * THIS NEEDS TO BE CHECKED!!!!!
    */
  private[this] def sysRegistryCheck(memFile: String, os: String, kdbg: String): Vector[String] = {

    val key1 =  "\"SOFTWARE\\Microsoft\\CurrentVersion\\RunOnce\""
    val key2 = "\"SOFTWARE\\Microsoft\\CurrentVersion\\Policies\\Explorer\\Run\""
    val key3 = "\"SOFTWARE\\Microsoft\\CurrentVersion\\Run\""
    val key4 = "\"SYSTEM\\CurrentControlSet\\Services\""
    val key5 = "\"SYSTEM\\CurrentControlSet\\Control\\" +
      "Session Manager\\" + "Memory Management\\" + "PrefetchParameters\""

    var runOnce = ""
    var run = ""
    var explorerRun = ""
    var prefetch = ""
    var service = ""

    if(kdbg.nonEmpty){
      runOnce = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key1".!!.trim ).getOrElse("")
      explorerRun =Try(s"python vol.py --conf-file=user_config.txt printkey -K $key2".!!.trim ).getOrElse("")
      run = Try(s"python vol.py --conf-file=user_config.txt $kdbg printkey -K $key3".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key5".!!.trim ).getOrElse("")
      service = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key4".!!.trim ).getOrElse("")
    } else{
      runOnce = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key1".!!.trim ).getOrElse("")
      explorerRun =Try(s"python vol.py -f $memFile --profile=$os printkey -K $key2".!!.trim ).getOrElse("")
      run = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key3".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key5".!!.trim ).getOrElse("")
      service = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key4".!!.trim ).getOrElse("")
    } // END if/else


    val vec: Vector[String] = {
      Vector(runOnce, explorerRun, run, service, prefetch)
    }

    return vec
  } // END sysRegistryCheck()

  /** Get the results of checking user registry keys sometimes indicative of persistence or anti-forensics */
  private[this] def userRegistryCheck(memFile: String, os: String, kdbg: String): Vector[String] = {
    val key1 =  "\"SOFTWARE\\Microsoft\\" + "Windows NT" + "\\CurrentVersion\\Windows\""
    val key2 = "\"SOFTWARE\\Microsoft\\" + "Windows NT" + "\\CurrentVersion\\Windows\\Run\""
    val key3 = "\"SOFTWARE\\Microsoft\\CurrentVersion\\Windows\\Run\""
    val key4 = "\"SOFTWARE\\Microsoft\\CurrentVersion\\Windows\\RunOnce\""
    val key5 = "\"SOFTWARE\\Microsoft\\CurrentVersion\\Windows\\RunOnceEx\""

    var runOnce = ""
    var run = ""
    var explorerRun = ""
    var prefetch = ""
    var service = ""

    /** The variable names here are wrong, but I don't want to deal w/ it. */
    if(kdbg.nonEmpty){
      runOnce = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key1".!!.trim ).getOrElse("")
      explorerRun =Try(s"python vol.py --conf-file=user_config.txt printkey -K $key2".!!.trim ).getOrElse("")
      run = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key3".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key5".!!.trim ).getOrElse("")
      service = Try(s"python vol.py --conf-file=user_config.txt printkey -K $key4".!!.trim ).getOrElse("")
    } else{
      runOnce = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key1".!!.trim ).getOrElse("")
      explorerRun =Try(s"python vol.py -f $memFile --profile=$os printkey -K $key2".!!.trim ).getOrElse("")
      run = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key3".!!.trim ).getOrElse("")
      prefetch = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key5".!!.trim ).getOrElse("")
      service = Try(s"python vol.py -f $memFile --profile=$os printkey -K $key4".!!.trim ).getOrElse("")
    } // END if/else

    return Vector(runOnce, explorerRun, run, service, prefetch)
  } // END userRegistryCheck()

  /** Need to add ethscan plugin. */
  def pcap(memFile: String, os: String, dump: String) = {
    Try(s"python vol.py -f $memFile --profile=$os ethscan -C $dump/out.pcap".! ).getOrElse("")
  }

}
