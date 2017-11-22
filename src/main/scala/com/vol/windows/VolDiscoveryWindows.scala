package com.bbs.vol.windows

import com.bbs.vol.utils
import StringOperations._
import com.bbs.vol.utils.{CaseTransformations, SearchRange}

/**
  * @author J. Alexander
  * @version 1.0
  *
  *      Program Purpose: Automate volatility discovery commands and
  *      store them in variables that we can parse and use in another program.
  */

// import com.bigbrainsecurity.utils.nlp.StringOperations._

import com.bbs.vol.httpclient.{WhoIs, PageInfo}
import java.io.File
import java.util.Calendar

import scala.collection.mutable.ArrayBuffer
import scala.io.Source
import scala.util.Try
// import org.apache.commons.net.whois.WhoisClient

// import scala.collection.mutable
import sys.process._

/**
  * IDEAS:
  * Write loop to create regexes like this "\w+system32/\w+[kernel32.dll]
  * - the [kernel32.dll] part of regex can be created using list generated from prefetch parser.
  * - Look for DLLs: ws2_32.dll, crypt32.dll, hnetcfg.dll, pstorec.dll
  */

/**
  * TO DO!!!!
  *
  * 1. Create a directory to store the following:
  * - Send pcap files to file
  * - Extract MFT
  * - Extract Log Files.
  * 2. Write Config File.
  * 3. Fix Bugs.
  */

/********************************* CASE CLASSES ************************/

/** Stores shimcache entries */
final case class ShimCache(lastMod: String, lastUpdate: String, path: String){
  override def toString(): String = {
    s"\n\nShimcache Entries:\nPath: $path\nLast Modified: $lastMod\nLast Updated: $lastUpdate\n"
  }

}

/** Store services and privileges info */
final case class SysState(svcOnePerLine: Vector[String], // Each service on one line w/ sections pipe separated
                    svcStopped: Vector[String],    // Suspicious services that were found stopped
                    consoles: String,              // Full Output of consoles scan.
                    suspCmds: Vector[String],      // If any suspicious commands were run (even though not always suspicious)
                    envVars: String )              // Full output of envars scan

/** Stores all of the raw data we discovered. This class will be returned from main. */
final case class Discovery( proc: (Vector[ProcessBbs], String),               // (All process info, processTree)
                            sysState: SysState,                            // SysState
                            net: (Vector[NetConnections], Vector[PageInfo]), // (connection Info, Whois Lookup)
                            rootkit: RootkitResults,                       // RootkitResults
                            remoteMapped: Vector[(String, String)],        // (pid -> RemoteMappedDrive Found)
                            registry: (Vector[String], Vector[String]),     // (User Registry, System Registry)
                            shimCache: String,
                            mftFileName: String
                          )

/**
  * Need to Return:
  * SysState
  * sysRegistry: Vector[String]
  * userRegistry: Vector[String]
  * whoisResult: V[String]
  * netScan: Vector[NetConnections]
  * processScanResults: (Vector[ProcessBbs], String)
  * rootkitHunt: RootkitResults
  * remoteMapped: Vector[(String, String)]
  * */

/** Stores individual process info that will be passed on to the next phase of program */
final case class ProcessBbs( pid: String,
                    offset: String,               // offset
                    name: String,                 // name of process
                    ppid: String,                 // parent ID
                    timeCreated: String,          // what time created?
                    hidden: Boolean = true) { // is this process hidden

  override def toString: String = {
    s"pid: $pid  \tname: $name \tppid: $ppid \ttime: $timeCreated \thidden: $hidden."
  }

  /** Accepts a Vector of current processes and finds parent name is */
  def parentName(vec: Vector[ProcessBbs]): String = {
    val parent = for {
      proc <- vec
      if this.ppid == proc.pid
    } yield proc.name

    if (ppid == "0") s"None"
    else parent.mkString
  } // END parentName()

  /** Get the full object for the parent process of the process */
  def parentObj(vec: Vector[ProcessBbs]): ProcessBbs = {

    val parent = for {
      proc <- vec
      if this.ppid == proc.pid
    } yield proc

    if (parent.isEmpty) new ProcessBbs("0", "0", "Unknown", "0", "0")
    else parent(0)
  } // END parentName()

  /** I'm not sure if this method works. Recursion is scary. */
  def getParents(vec: Vector[ProcessBbs]): Vector[ProcessBbs] = {

    val result: Vector[ProcessBbs] = for{
      value <- vec
      if value.ppid == ppid
    } yield value

    if (this.ppid == "0") result
    else if(result.isEmpty) result
    else  result(0) +: result(0).getParents(vec)

  } // END getParents()
} // END ProcessBbs class

/****************************************************
  ***************************************************
  ******************~~~~~RUN~~~~*********************
  ***************************************************
  ***************************************************/

/********************** AutomateVolDiscoveryWindows object ***********************/
object VolDiscoveryWindows extends VolParse {

  /**
    * This is the functional main method for performing our initial
    * volatility scans. Based on these results, we'll perform more scans.
    */
  private[windows] def run(memFile: String, os: String, kdbg: String, dump: String ): Discovery = {

    /************************ PERFORM VOLATILITY SCANS **************************/

    // Params (debugOffset: List[String] -look at head, objType: List[ObjTypeScanResults)
    //val initialScan: InitialScanResults = InitialScan.run(os, memFile)

    /** Contains Vector of processes and a ProcessBbs Tree */
    val processScanResults: (Vector[ProcessBbs], String) = ProcessBbsScan.run(memFile, os, kdbg)


    // val testGetParents = processScanResults._1
    // val parents = testGetParents(4).getParents(testGetParents)

    // println("Trying to print parents...")
    // parents.foreach(println)

    /**
      * WARNING!!!!
      *
      * NEED TO FIX HOW PROCESSES ARE PARSED TO INCLUDE PROCESSES W/ SPACES!!!
      *
      */

    //processScanResults._1.foreach(println) // printing psscan after it was parsed
    //println("\nPrinting process tree results:\n\n")
    //println(processScanResults._2) // Printing processtree

    /** Scan network connections */
    val netScanResult : (Vector[NetConnections], Vector[PageInfo]) = NetScan.run(memFile, os, kdbg)
    println("\n\nPrinting scan for network connections...\n\n")
    netScanResult._1.foreach(println)
    netScanResult._2.foreach(println)

    val remoteMapped: Vector[(String, String)] = RemoteMappedDriveSearch.run(memFile, os, kdbg)
    println("\n\nPrinting remote mapped drives found...\n\n")
    remoteMapped.foreach(println)

    val rootkitHunt = RootkitDetector.run(memFile, os, kdbg)

    /** Contains suspicious SIDs and suspicious usernames */
   // val suspiciousSIDs: mutable.Map[String, String] = DetectLateralMovement.run(memFile, os)

   val shimCache = shimCacheEntries(memFile, os, kdbg)
   var sysRegistry = Vector.empty
    var userRegistry = Vector.empty

    if(os.contains("WinXp") || os.contains("Win2003")){
      sysRegistry ++: sysRegistryCheckXP(memFile, os, kdbg)
      userRegistry ++: userRegistryCheckXP(memFile, os, kdbg)
    }else{
      sysRegistry ++: sysRegistryCheck(memFile, os, kdbg)
      userRegistry ++: userRegistryCheck(memFile, os, kdbg)
    }


    /****************************************************************************
      ***************************************************************************
      * THIS NEEDS TO BE BASED ON THE VERSIONS OF WINDOWS THEY ARE RUNNING!!!!
      ***************************************************************************
      ***************************************************************************/

    println("\nPrinting Significant System Registry Keys:\n\t")
    sysRegistry.foreach(println)

    println("\n\nPrinting Significant User Registry Keys:\n\t")
    userRegistry.foreach(println)

    println("\n\nExtracting Event Logs...")
    // extractEVT(memFile, os, dump)
    println("\n\nEvent logs successfully extracted.\n\nExtracting Master File Table...")
    val mftFilename = extractMFT(memFile, os, kdbg, dump)

    println("\n\nAnalyzing Windows services and gathering information about system state...\n")
    val sysState: SysState = SysStateScan.run(memFile, os, kdbg)

    /** Returns a Discovery case class */
    Discovery(processScanResults, sysState, netScanResult, rootkitHunt,
              remoteMapped, (userRegistry, sysRegistry), shimCache, mftFilename)

  } // END run()

  private[this] def cleanProcScan(vec: Vector[ProcessBbs]) = {

  }
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

  /** Extract the MFT */
  private[this] def extractMFT(memFile: String, os: String, kdbg: String, dump: String): String = {
    /** Create directory to store mft dump in. */
    val mftDir = dump + "/" + "mft_dump/"
    val dir = new File(mftDir)
    dir.mkdir()

    // val csvFileName = memFile + Calendar.HOUR + "-" + Calendar.MINUTE + ".csv"
    val mftFileName: String = memFile + "_MFT" + ".body"
    // Outputting MFT as body file so it's easily parsed w/ sleuthkit

    if(kdbg.nonEmpty) {
      Try(s"python vol.py --conf-file=user_config.txt mftparser --output=body --dump-dir=$mftDir --output-file=$mftFileName".!)
        .getOrElse(println("Failed to extract mft body file.\n"))
    }else{
      Try(s"python vol.py -f $memFile --profile=$os mftparser --output=body --dump-dir=$mftDir --output-file=$mftFileName".! )
        .getOrElse(println("Failed to extract mft body file.\n"))
    }

    return mftFileName
  } // END extractMFT()

  private[this] def extractEVT(memFile: String, os: String, kdbg: String, dump: String): Unit = {
    /**
      * Events we want to look for:
      * Unsuccessful logons:
      * -- 529 with failure
      * -- 680 with failure
      * -- 100
      * -- powershell related logs
      */

    if (os.startsWith("WinXP") || os.startsWith("Win2003")) {
      // saved result is pipe separated txt file with Date/Time|Log Name| Computer Name|SID|Source|EventID|Event Type|Message
      if (kdbg.nonEmpty) {
        Try(s"python vol.py --conf-file=user_config.txt evtlogs -v --save-evt -D $dump".!).getOrElse("")
      } else {
        Try(s"python vol.py -f $memFile --profile=$os dumpfiles --regex .evtx$$ --ignore-case --dump-dir $dump".!).getOrElse("")
      }
    }
  } // END extractEVT

  /**
    * Methods for checking registry keys.
    * NOTE: In version 2 this should be much more thorough:
    * == First need to find the current control set p.291-292. then printkey "HKLM\\SYSTEM\\CurrentControlSet\\Services" and check against timeline.
    * == can also print shimcache
    * == Should also check for timestomping in registry
    */

  private[this] def shimCacheEntries(memFile: String, os: String, kdbg: String): String = {

    var shimcache = ""
    if(kdbg.nonEmpty){
      shimcache = Try( s"python vol.py --conf-file=user_config.txt shimcache".!!.trim ).getOrElse("")
    }else {
      shimcache = Try(s"python vol.py -f $memFile --profile=$os shimcache".!!.trim).getOrElse("")
    }

    val shimCacheVec = parseOutputDashVec(shimcache)
    val shim2D = vecParse(shimCacheVec.getOrElse(Vector[String]()))

    val shimVec: Vector[ShimCache] = shim2D.getOrElse(Vector[Vector[String]]())
      .map(x => ShimCache(Try(x(0)).getOrElse("") +  " " + Try(x(1)).getOrElse("") + " " + Try(x(2)).getOrElse(""),
        Try(x(3)).getOrElse("") + " " + Try(x(4)).getOrElse("") + " " + Try(x(5)).getOrElse(""),
        Try(x(6)).getOrElse("") + " " + Try(x(7)).getOrElse("") + " " + Try(x(8)).getOrElse("") + " " +
          Try(x(9)).getOrElse("") + " " + Try(x(10)).getOrElse("").trim))
    //index 6
    // val trimShim = shimVec.map(_.trim)
    println("Print shimcache column values: \n")
    for{
      value <- shimVec
    } println(value + "\n")


    return shimcache
  } // END shimCacheEntries()
  /**
    * Get the results of checking system registry keys sometimes indicative of persistence
    *
    * THIS NEEDS TO BE CHECKED!!!!!
    */
  private[this] def sysRegistryCheck(memFile: String, os: String, kdbg: String): Vector[String] = {
    val quote = "\""

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
} // END AutomateVolDiscoveryWindows object

/** ******************** ProcessBbsScan object ************************/

/** Stores information about a single scary process that we discovered using the psxview scan */

// case class RepeatFiles(malwareFound: Boolean, process: String, repeated: Vector[String])


object ProcessBbsScan extends VolParse with CaseTransformations {

  /** Functional main method of ProcessBbsScan object */
  private[windows] def run( memFile: String, os: String, kdbg: String ): (Vector[ProcessBbs], String) = {

    println("\nRunning psscan...\n")
    /** Returns Tuple with a map of pid -> info about processes and info about repeatFiles */
    val psScanResult: Vector[ProcessBbs] = psScan(memFile, os, kdbg)

    println("\nRunning pslist scan...\n")
    val psList: Vector[ProcessBbs] = psListScan(memFile, os, kdbg)
    val psListPid = psList.map(x => x.pid)
    // val psxviewResult: Vector[Vector[String]] = psxScan(memFile, os)
    val psTreeResult: String = psTreeScan(memFile, os, kdbg)

    /** Filter psxviewResult to only those w/ matching PIDs in psscan */
    val shouldBeFalse: Vector[ProcessBbs] = {
      psScanResult.filter((x: ProcessBbs) => psListPid.contains(x.pid))
    }

    val changeNotHidden: Vector[ProcessBbs] = {
      shouldBeFalse.map((x: ProcessBbs) => ProcessBbs(x.pid, x.offset, x.name, x.ppid, x.timeCreated, hidden = false))
    }

    /** Combine this with diff and we're set */
    val diffVec: Vector[ProcessBbs] = psScanResult.diff(shouldBeFalse)

    val procVector: Vector[ProcessBbs] = {
      diffVec ++: changeNotHidden
    }
    /** I could use distinct here, but I was too excited about distinctBy to not use it. */
    val distinctProcess = distinctBy(procVector)(_.pid)

    println("Printing cleaned up process list results...\n\n")
    distinctProcess.foreach(println)

    return (distinctProcess, psTreeResult)
  } // END run()

  /**
    * WARNING!!!
    *
    * This logic does not seem correct. Shouldn't this be pslist?
    * */
  /****************************************************************************
    * NEED TO CHANGE LOGIC TO DEAL WITH SPACES!!!!!!!
    ***************************************************************************/


  private[this] def psListScan(memFile: String, os: String, kdbg: String): Vector[ProcessBbs] = {

    println("\n\nRunning pslist...\n\n")

    var psScan = ""
    if (kdbg.nonEmpty)

      psScan = Try(s"python vol.py --conf-file=user_config.txt pslist".!!.trim ).getOrElse("Failed")
    else
      psScan = Try( s"python vol.py -f $memFile --profile=$os pslist".!!.trim ).getOrElse("")
    println("Printing pslist result\n")
    println(psScan)
    val psScanParse: Vector[String] = parseOutputDashVec( psScan ).getOrElse(Vector[String]())
    val psScanWithCol: Vector[Vector[String]] = vecParse( psScanParse ).getOrElse( Vector[Vector[String]]() )

    // We are going to skip this for now.
    // This will be a problem because we need to make sure they have different PIDs.
    /**
    // (filename, pid)
      val psFilenames: Vector[(String, String)] = psScanWithCol.map(x => (x(1), x(2)))

      val repeats = psFilenames.map(x => x._1.toUpperCase())
        .filterNot(_.contains("SYSTEM32/CSRSS.EXE"))
        .filterNot(_.contains("SYSTEM32/SVCHOST.EXE"))

      /** Figure out which of the processes are repeated. */
      val repeatedFiles: Vector[String] = repeats.diff(repeats.distinct).distinct

      if (repeatedFiles.contains("LSASS.EXE")){
        malwareFound = (true, "lsass.exe")
      }
      if (repeatedFiles.contains("SERVICES.EXE")){
        malwareFound = (true, "Services.exe")
      }

      // Stored information about repeated files.
      val repeated: RepeatFiles = RepeatFiles(malwareFound._1, malwareFound._2, repeatedFiles)
      */
    val psScanResult: Vector[ProcessBbs] = filterPsScan(psScanWithCol)

    return psScanResult
  } // END psScan()

  /** Changing the way the map is created to get around */
  private[this] def filterPsList(vec: Vector[Vector[String]])  = {

    var finalVec = Vector[ProcessBbs]()

    val processVec: Vector[ProcessBbs] = for {
      row <- vec
      if row.size >= 7
    } yield grabProcessList(row)

    /** Remove values w/ empty */
    val procVec = for{
      process <- processVec
      if process.pid != "Empty"
    } yield process

    val procNoInfo: Vector[ProcessBbs] = for{
      row <- vec
      if row.size < 10
    } yield shortProcessList(row)

    if (procNoInfo.nonEmpty){
      finalVec = procVec ++: procNoInfo
      finalVec
    }else{
      procVec
    }
    /***********************************************
      * We still need to filter out duplicate pids
      **********************************************/
    // return procVec
  } // filterPsList()

  private[this] def shortProcessList(vector: Vector[String]) = {

    val vec = vector.map(_.toLowerCase)

    if (Try(vec(2).toInt).isSuccess) {
      ProcessBbs(Try(vec(2).trim).getOrElse("UNKNOWN"), Try(vec(0).trim).getOrElse("0x0"),
        Try(vec(1).trim).getOrElse("UNKNOWN"), Try(vec(3).trim).getOrElse("0"),
        Try(vec(8).trim).getOrElse("???") + " " + Try(vec(9).trim).getOrElse("???") + "  " + Try(vec(10)).getOrElse("???"))
    }else if (Try(vec(3).toInt).isSuccess){
      ProcessBbs(Try(vec(3).trim).getOrElse("UNKNOWN"), Try(vec(0).trim).getOrElse("0x0"),
        Try(vec(1).trim).getOrElse("UNKNOWN") + Try(vec(2).trim).getOrElse(""), Try(vec(4).trim).getOrElse("0"),
        Try(vec(6).trim).getOrElse("???") + " " + Try(vec(7).trim).getOrElse(""))
    }else{
      ProcessBbs(Try(vec(2)).getOrElse("UNKNOWN"), Try(vec(0)).getOrElse(""), Try(vec(1).trim).getOrElse(""),
        Try(vec(3)).getOrElse("0"), "")
    }

  } // END shortProcess()

  /** Makes sure that we can handle processes that have spaces in their names */
  private[this] def grabProcessList(vector: Vector[String]): ProcessBbs = {

    val vec = vector.map(_.toLowerCase)

    /** This needs to check if the value at index after the process name is all numbers. */

    if (Try(vec(2).toInt).isSuccess) {
      ProcessBbs(vec(2).trim, vec(0).trim, vec(1).trim, vec(3).trim, Try(vec(8).trim + " " + vec(9).trim).getOrElse("UNKNOWN"))
    }
    else if(Try(vec(3).toInt).isSuccess){
      ProcessBbs(vec(3).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim, vec(4).trim,
        Try(vec(9).trim + " " + vec(10).trim).getOrElse("UNKNOWN"))
    }
    else if (Try(vec(4).toInt).isSuccess) {
      ProcessBbs(vec(4).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim,
        vec(5).trim, Try(vec(10).trim + " " + vec(11).trim).getOrElse("UNKNOWN"))
    }
    else if (Try(vec(5).toInt).isSuccess) {
      ProcessBbs(vec(5).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim,
        vec(6).trim, Try(vec(11).trim + " " + vec(12).trim).getOrElse("UNKNOWN"))
    }
    else if (Try(vec(6).toInt).isSuccess) {
      ProcessBbs(vec(6).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
        " " + vec(5).trim, vec(7).trim, Try(vec(12).trim + " " + vec(13).trim).getOrElse("UNKNOWN"))
    }
    else if (Try(vec(7).toInt).isSuccess) {
      ProcessBbs(vec(7).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
        " " + vec(5).trim + " " + vec(6).trim, vec(8).trim, Try(vec(13).trim + " " + vec(14).trim).getOrElse("UNKNOWN"))
    }
    else if (Try(vec(8).toInt).isSuccess) {
      ProcessBbs(vec(8).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
        " " + vec(5).trim + " " + vec(6).trim + " " + vec(7).trim, vec(9).trim,
        Try(vec(11).trim + " " + vec(12).trim).getOrElse("UNKNOWN"))
    } // END if statements
    else ProcessBbs("Empty", "Empty","Empty","Empty", "Empty")
  } // END grabProcess()


  private[this] def psScan(memFile: String, os: String, kdbg: String): Vector[ProcessBbs] = {

    println("\n\nRunning psscan...\n\n")

    var psScan = ""
    if(kdbg.nonEmpty) {
      psScan = Try(s"python vol.py --conf-file=user_config.txt psscan".!!.trim).getOrElse("Failed")
      println("psScan test:\n")
      println(psScan)
    }else
      psScan= Try( s"python vol.py -f $memFile --profile=$os psscan".!!.trim ).getOrElse("")

    val psScanParse: Vector[String] = parseOutputDashVec( psScan ).getOrElse(Vector[String]())
    val psScanWithCol: Vector[Vector[String]] = vecParse( psScanParse ).getOrElse( Vector[Vector[String]]() )

    // We are going to skip this for now.
    // This will be a problem because we need to make sure they have different PIDs.
    /**
    // (filename, pid)
      val psFilenames: Vector[(String, String)] = psScanWithCol.map(x => (x(1), x(2)))

      val repeats = psFilenames.map(x => x._1.toUpperCase())
        .filterNot(_.contains("SYSTEM32/CSRSS.EXE"))
        .filterNot(_.contains("SYSTEM32/SVCHOST.EXE"))

      /** Figure out which of the processes are repeated. */
      val repeatedFiles: Vector[String] = repeats.diff(repeats.distinct).distinct

      if (repeatedFiles.contains("LSASS.EXE")){
        malwareFound = (true, "lsass.exe")
      }
      if (repeatedFiles.contains("SERVICES.EXE")){
        malwareFound = (true, "Services.exe")
      }

      // Stored information about repeated files.
      val repeated: RepeatFiles = RepeatFiles(malwareFound._1, malwareFound._2, repeatedFiles)
      */
    val psScanResult: Vector[ProcessBbs] = filterPsScan(psScanWithCol)

    return psScanResult
  } // END psScan()

  /** Changing the way the map is created to get around */
  private[this] def filterPsScan(vec: Vector[Vector[String]])  = {

    var finalVec = Vector[ProcessBbs]()

    val processVec: Vector[ProcessBbs] = for {
      row <- vec
      if row.size >= 7
    } yield grabProcess(row)

    /** Remove values w/ empty */
    val procVec = for{
      process <- processVec
      if process.pid != "Empty"
    } yield process

    val procNoInfo: Vector[ProcessBbs] = for{
      row <- vec
      if row.size < 7
    } yield shortProcess(row)

    if (procNoInfo.nonEmpty){
      finalVec = procVec ++: procNoInfo
      finalVec
    }else{
      procVec
    }
    /***********************************************
      * We still need to filter out duplicate pids
      **********************************************/
   // return procVec
  } // filterPsScan()

  private[this] def shortProcess(vector: Vector[String]) = {

    val vec = vector.map(_.toLowerCase)

    if (Try(vec(2).toInt).isSuccess) {
      ProcessBbs(Try(vec(2).trim).getOrElse("UNKNOWN"), Try(vec(0).trim).getOrElse("0x0"),
        Try(vec(1).trim).getOrElse("UNKNOWN"), Try(vec(3).trim).getOrElse("0"),
        Try(vec(5).trim).getOrElse("???") + " " + Try(vec(6).trim).getOrElse("???") + Try(vec(7)).getOrElse("???"))
    }else if (Try(vec(3).toInt).isSuccess){
      ProcessBbs(Try(vec(3).trim).getOrElse("UNKNOWN"), Try(vec(0).trim).getOrElse("0x0"),
        Try(vec(1).trim).getOrElse("UNKNOWN") + Try(vec(2).trim).getOrElse(""), Try(vec(4).trim).getOrElse("0"),
        Try(vec(6).trim).getOrElse("???") + " " + Try(vec(7).trim).getOrElse(""))
    }else{
      ProcessBbs(Try(vec(2)).getOrElse("UNKNOWN"), Try(vec(0)).getOrElse(""), Try(vec(1).trim).getOrElse(""),
        Try(vec(3)).getOrElse("0"), "")
    }


  } // END shortProcess()

  /** Makes sure that we can handle processes that have spaces in their names */
  private[this] def grabProcess(vector: Vector[String]): ProcessBbs = {


    val vec = vector.map(_.toLowerCase)

    /** This needs to check if the value at index after the process name is all numbers. */

  if (Try(vec(2).toInt).isSuccess) {
      ProcessBbs(vec(2).trim, vec(0).trim, vec(1).trim, vec(3).trim, vec(5).trim + " " + vec(6).trim)
    }
  else if(Try(vec(3).toInt).isSuccess){
      ProcessBbs(vec(3).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim, vec(4).trim,
        vec(6).trim + " " + vec(7).trim)
    }
  else if (Try(vec(4).toInt).isSuccess) {
      ProcessBbs(vec(4).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim,
        vec(5).trim, vec(7).trim + " " + vec(8).trim)
    }
  else if (Try(vec(5).toInt).isSuccess) {
      ProcessBbs(vec(5).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim,
        vec(6).trim, vec(8).trim + " " + vec(9).trim)
    }
  else if (Try(vec(6).toInt).isSuccess) {
    ProcessBbs(vec(6).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
      " " + vec(5).trim, vec(7).trim, vec(9).trim + " " + vec(10).trim)
  }
  else if (Try(vec(7).toInt).isSuccess) {
    ProcessBbs(vec(7).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
      " " + vec(5).trim + " " + vec(6).trim, vec(8).trim, vec(10).trim + " " + vec(11).trim)
  }
  else if (Try(vec(8).toInt).isSuccess) {
    ProcessBbs(vec(8).trim, vec(0).trim, vec(1).trim + " " + vec(2).trim + " " + vec(3).trim + " " + vec(4).trim +
      " " + vec(5).trim + " " + vec(6).trim + " " + vec(7).trim, vec(9).trim, vec(11).trim + " " + vec(12).trim)
  } // END if statements
  else ProcessBbs("Empty", "Empty","Empty","Empty", "Empty")
  } // END grabProcess()
  /** Deprecated in favor of faster logic. */
/*
  /** Check if every value in a string is a number.*/
  private[this] def allNumbers(str: String): Boolean = {
    val charArr = str.toCharArray
    val numBool: Array[Int] = charArr.map(x => Try(x.toInt).getOrElse(1234567))

    if (numBool.contains(1234567)) false
    else true
  } // END allNumbers
  */
  /**
    * psxScan()
    * Does psxScan and finds hidden processes and possibly hidden processes
    * @param memFile memory dump file
    * @param os os
    * @return (Vector[PsxScaryProc], Vector[PsxScaryProc])
    *         returns scary processes and processes that should be investigated.
    */
  private[this] def psxScan(memFile: String, os: String, kdbg: String): Vector[Vector[String]] = {

    println("\n\nRunning psxview scan...\n\n")

    var psxView = ""
    /** DO VARIETY OF PROCESS SCANS */
    // If you see False in the splits column, there’s a problem.
    if(kdbg.nonEmpty) {
      psxView = {
        Try(s"python vol.py --conf-file=user_config.txt —apply-rules".!!.trim)
          .getOrElse("\n\npsxview scan failed. It's like that there is something wrong with your settings.")
      }
    }else{
      psxView = {
        Try(s"python vol.py -f $memFile --profile=$os psxview —apply-rules".!!.trim)
          .getOrElse("\n\npsxview scan failed. It's like that there is something wrong with your settings.")
      }
    }
    println("\n\nPrinting psxview scan...\n\n")
    println(psxView)

    val psxViewParse: Vector[String] = parseOutputDashVec( psxView ).getOrElse( Vector[String]() )
    val psxWithColumns: Vector[Vector[String]] = vecParse( psxViewParse ).getOrElse( Vector[Vector[String]]() )

    val filtered = for{
      row <- psxWithColumns
      if Try(row(2).toInt).isSuccess
    } yield Vector(row(0), row(1), row(2), row(3), row(4))

    val filteredFalse = for{
      row <- filtered
      if row(3).toLowerCase.contains("true")
    }yield Vector(row(0), row(1), row(2), row(3), row(4))

    val filtered2 = for{
      row <- psxWithColumns
      if Try(row(3).toInt).isSuccess
    } yield Vector(row(0), row(1) + " " + row(2), row(3), row(4), row(5))

    val filtered2False = for{
      row <- psxWithColumns
      if row(4).toLowerCase == "true"
    } yield Vector(row(0), row(1) + " " + row(2), row(3), row(4), row(5))

    val filtered3 = for{
      row <- psxWithColumns
      if Try(row(4).toInt).isSuccess
    } yield Vector(row(0), row(1) + " " + row(2) + " " + row(3), row(4), row(5), row(6))


    val filtered3False = for{
      row <- psxWithColumns
      if row(5).toLowerCase == "true"
    } yield Vector(row(0), row(1) + " " + row(2) + " " + row(3), row(4), row(5), row(6))

    val filtered4 = for{
      row <- psxWithColumns
      if Try(row(5).toInt).isSuccess
    } yield Vector(row(0), row(1) + " " + row(2) + " " + row(3) + " " + row(4), row(5), row(6), row(7))

    val filtered4False = for{
      row <- psxWithColumns
      if row(6).toLowerCase == "true"
    } yield Vector(row(0), row(1) + " " + row(2) + " " + row(3) + " " + row(4), row(5), row(6), row(7))

    val filterPsx = filteredFalse ++: filteredFalse ++: filtered2False ++: filtered3False ++: filtered4False

    // val fixedContradiction: Vector[Vector[String]] = removeContradictions(filterPsx, psxWithColumns)


    return filterPsx
  } // psxScan

  private[this] def psTreeScan(memFile: String, os: String, kdbg: String): String = {

    println("\n\nRunning pstree scan...\n\n")

    var pstree = ""
    if(kdbg.nonEmpty){
      pstree = Try( s"python vol.py --conf-file=user_config.txt pstree".!!.trim )
        .getOrElse("pstree scan failed...\n\nIt is likely that something is wrong with your settings.\n\n")
    }else{
      pstree = Try( s"python vol.py -f $memFile --profile=$os pstree".!!.trim )
        .getOrElse("pstree scan failed...\n\nIt is likely that something is wrong with your settings.\n\n")
    }

    println("\n\nPrinting pstree scan...\n\n")
    println(pstree)

    return pstree
  } // END psTreeScan

} // END ProcessBbsScan object
// (pid, destination IP)


final case class NetConnections( pid: String,
                                 proto: String,
                                 srcIP: String,
                                 destIP: String,
                                 vnc: Boolean,               // Check if VNC port 5500 is listening.
                                 unknownSrcIp: Boolean,
                                 unknownDestIp: Boolean){
  override val toString = {
    s"\n\nPID: $pid\nSource IP: $srcIP\nDestination IP: $destIP\nProtocol: $proto\nVNC Port Found: $vnc\n\n"
  }
} // END NetConnections class

/************************* Netscan Object *************************/
object NetScan extends VolParse with SearchRange {
  private[windows] def run( memFile: String, os: String, kdbg: String ): (Vector[NetConnections], Vector[PageInfo]) = {
    // SKIPPING netscan for now.
    // val socketsAndConnections: Option[String] = Some( s"python vol.py -f $memFile --profile=$os netscan".!!.trim )
    // val netscanParse = parseOutputDropHead( socketsAndConnections.getOrElse( "" ) ).get

    var net = ""
    var conn = ""
    if(os.contains("WinXP") | os.contains("Win2003")){
      if(kdbg.nonEmpty){
        conn = {
          Try( s"python vol.py --conf-file=user_config.txt connscan".!!.trim )
            .getOrElse("\n\nconnscan failed...\n\n")
        }
        println("\nPrinting connscan results: ")
        println(conn)
      }
      else {
        conn = {
          Try( s"python vol.py -f $memFile --profile=$os connscan".!!.trim ).getOrElse("\n\nconnscan failed...\n\n")
        }
        println("\nPrinting connscan results: ")
        println(conn)
      }
      // run connscan
    }else{
      if(kdbg.nonEmpty){
        net = {
          Try( s"python vol.py --conf-file=user_config.txt netscan".!!.trim ).getOrElse("\n\nconnscan failed...\n\n")
        }
        println("\nPrinting netscan results: ")
        println(net)
      } else{
          net = {
            Try( s"python vol.py -f $memFile --profile=$os netscan".!!.trim ).getOrElse("\n\nconnscan failed...\n\n")
          }
        println("\nPrinting netscan results: ")
        println(net)
        }
      } // if/else kdbg.nonEmpty

    /** Decide which Information we return conn or netScan */
    if(conn.nonEmpty){
      // The output could probably be saved in a Map[Int, String] with the PID as the key
      val (conns, outsideConns): (Vector[NetConnections], Vector[String]) = connScan(conn)

      var whois = Vector[String]()

      if(outsideConns.isEmpty) (conns, Vector[PageInfo]())
      else (conns, whoisLookup(outsideConns))
    }else{
      val (netResult, outsideConns): (Vector[NetConnections], Vector[String]) = netScan(net)

      if(outsideConns.isEmpty) (netResult, Vector[PageInfo]())
      else(netResult, whoisLookup(outsideConns))
    } // END if conn.NonEmpty

  } // END run()

  private[this] def netScan(net: String): (Vector[NetConnections], Vector[String]) = {

    val netParsed: Vector[String] = Source.fromString(net)
      .getLines
      .dropWhile(!_.contains("Offset"))
      .dropWhile(_.contains("Offset"))
      .toVector

    val net2d: Vector[Vector[String]] = vecParse(netParsed).getOrElse(Vector[Vector[String]]())

    val includesListening = for{
      value <- net2d
      if value(4) != "LISTENING" || value(4) != "CLOSED" || value(4) != "ESTABLISHED"
    } yield Vector(value(0).trim, value(1).trim, value(2).trim, value(3).trim, "NOINFO", value(5).trim, value(5).trim,
      Try(value(6)).getOrElse("") + " " + Try(value(7)).getOrElse("") + " " + Try(value(8)).getOrElse(""))

    val discludesListening = for{
      value <- net2d
      if value(4) == "LISTENING" || value(4) == "CLOSED" || value(4) == "ESTABLISHED"
    } yield Vector(value(0).trim, value(1).trim, value(2).trim, value(3).trim, value(4).trim, value(5).trim, value(6).trim,
      Try(value(7)).getOrElse("") + " " + Try(value(8)).getOrElse("") + " " + Try(value(9)).getOrElse(""))

    val allListening = includesListening ++: discludesListening

    val connects = for {
      line <- allListening
      if {!line(2).startsWith("198") || !line(2).startsWith("10\\.") || !line(2).startsWith("172") &
        line(3).startsWith("198") || line(3).startsWith("10\\.") || line(3).startsWith("172")}
    } yield new NetConnections(getPid(line(4)) + getPid(line(5)) + getPid(line(6)),
      line(1), line(2), line(3), line(2).splitLast(':')(1) == "5800", true, false )
    // parse
    val connects2 = for {
      line <- allListening
      if {line(2).startsWith("198") || line(2).startsWith("10\\.") || line(2).startsWith("172\\.") &
        !line(3).startsWith("198") || !line(3).startsWith("10\\.") || !line(3).startsWith("172\\.")}
    } yield new NetConnections(getPid(line(4)) + getPid(line(5)) + getPid(line(6)),
      line(1), line(2), line(3), line(2).splitLast(':')(1) == "5800", false, true )
    // parse

    val connects3 = for{
      line <- allListening
      if {line(3).startsWith("198") || line(3).startsWith("10\\.") || line(3).startsWith("172\\.") &
        line(2).startsWith("198") || line(2).startsWith("10\\.") || line(2).startsWith("172\\.")}
    } yield new NetConnections(getPid(line(4)) + getPid(line(5)) + getPid(line(6)),
      line(1), line(2), line(3), line(2).splitLast(':')(1) == "5800", true, true )

    val foreignSrc = connects.map(x => x.srcIP)
      .filterNot(_.startsWith("10\\."))
      .filterNot(_.startsWith("192"))
      .filterNot(_.startsWith("172"))
      .filterNot(_.contains("0\\.0\\.0\\.0"))
      .filterNot(_ == "\\*:\\*")
    val foreignDest = connects.map(x => x.destIP)
      .filterNot(_.startsWith("10\\."))
      .filterNot(_.startsWith("192"))
      .filterNot(_.startsWith("172"))
      .filterNot(_.contains("0\\.0\\.0\\.0"))
      .filterNot(_ == "\\*:\\*")


    val allConnects = connects ++: connects2 ++: connects3

    println("Printing Netscan parsed")
    allConnects.foreach(println)
    val foreignIPs = foreignSrc ++: foreignDest

    (allConnects, foreignIPs)
} // END netScan()

  private[this] def getPid(str: String): String = {
    val pidSuccess = Try(str.toInt).isSuccess
    if(pidSuccess) str
    else ""
  } // END getPid

  /***************************************
    * NEED TO FIX LIKE NETSCAN WAS FIXED
    **************************************/
  /** Scan finds both open and closed network connections */
  private[this] def connScan(conn: String): (Vector[NetConnections], Vector[String]) = {

    println("\n\nPerforming connscan...\n\n")

    println("\n\nPrinting connscan results...\n\n")
    println(conn)

    val connParsed: Vector[String] = parseOutputDashVec(conn).getOrElse(Vector[String]())
    val conn2d: Vector[Vector[String]] = vecParse(connParsed).getOrElse(Vector[Vector[String]]())

    val connects = for {
      line <- conn2d
      if !line(1).startsWith("198") || !line(1).startsWith("10\\.") || !line(1).startsWith("172\\.")
    } yield new NetConnections(line(3), "ConnScan", line(1), line(2), line(2).splitLast(':')(1) == "5800", true, false )

    val connects2 = for {
      line <- conn2d
      if !line(2).startsWith("198") || !line(2).startsWith("10\\.") || !line(2).startsWith("172\\.")
    } yield new NetConnections(line(3), "ConnScan", line(1), line(2), line(2).splitLast(':')(1) == "5800", false, true )


    val destIps = connects.map(x => x.destIP)
    val srcIps = connects.map(x => x.srcIP)
    val ips = destIps ++: srcIps
    val foreignIps = ips.filterNot(_.startsWith("198")).filterNot(_.startsWith("172")).filterNot(_.startsWith("10\\."))

    return (connects, foreignIps)
  } // END connScan()

  private[this] def checkKnownIps(ip: String): Boolean = {


    false
  } // END checkKnownIps

  /** Loop through all outside ip addresses and return whois info
    * I'll filter the output when the rest of the program is done and I have free time.
    */
  private[this] def whoisLookup(vec: Vector[String]) = {
    val ips = vec.distinct

    val result = for(connection <- ips) yield getWhoIs(connection)

    val cleanedResult = result.filterNot(x => x.name.contains("Failed."))
    println("Printing whois lookup result...")
    cleanedResult.foreach(println)
    cleanedResult
  } // END whoisLookup()

  /** Look up info about ip address from whois and return information. */
  private[this] def getWhoIs(ipAddr: String): PageInfo = {

    /** Need to pull IP address out of the full name w/ port number */
    // Used splitLast() from StringOperations to ensure compatibility w/ IPv6
    val ipSplit: Array[String] = ipAddr.splitLast(':')

    println(s"Performing whois lookup for ip address: $ipAddr")
    val whois = new WhoIs(ipSplit(0))

    // check if IP address is from Microsoft, Apple, a backbone network provider, or other common subnets

    val whoisResult = Try(whois.query()).getOrElse(PageInfo("Connection Failed.","Connection failed", "", "", "", "", "", "", "", ""))
    /** Try to connect to whois to find information about */
    // Try(whois.connect("www.whois.arin.net")).getOrElse(println(response))

    return whoisResult
  } // END getWhoIs()
} // END NetScan object

/*************************** HistoryScan Object *************************/
object SysStateScan extends VolParse {

  /** A lot more could be done with this section. Especially for the services scan. */
  private[windows] def run( memFile: String, os: String, kdbg: String): SysState = {

    val (svcOnePerLine, svcStopped) = svcScan(memFile, os, kdbg)

    /** A lot of commands could be added to the suspicious commands. The full output is probably enough though. */
    val (fullConsoles, suspiciousCmds) = consoles(memFile, os, kdbg)

    /** envars scan contains information about environmental variables. Verbose output for now. */
    val env: String = envScan(memFile, os, kdbg)

    return SysState(svcOnePerLine, svcStopped, fullConsoles, suspiciousCmds, env)

    // Use verbose to locate DLLs hosting the service (String following "ServiceDll: "
    // - Malware commonly installs services using svchost.exe (Following "Binary Path: ") and implements malware in a DLL.

    // Need to put together a list of dlls that run out of System32 for each os and compare against system32 dlls for svhost

    // Only gives privileges that a process specifically enabled
    /**
    val priv: Option[String] = Some( s"python vol.py -f $memFile --profile=$os privs --silent".!!.trim )
    val privsParse = parseOutputDash( priv.getOrElse( "" ) ).get

    // NEED A LIST OF PRIVILEGES TO LOOK FOR

    // Scans for and parses potential Master Boot Records (MBRs)
    // NEED TO FIND OFFSET AND PASS THAT TO MBRPARSER!!
    val mbr: Option[String] = Some( s"python vol.py -f $memFile --profile=$os mbrparser -o $offset".!!.trim )
*/
  } // END run()

  /**
    * THIS SHOULD LOOK FOR ALL STOPPED SERVICES
    * LOOK FOR "Binary Path: -"
    */

  /** All the service scan related stuff runs out of this method. */
  private[this] def svcScan(memFile: String, os: String, kdbg: String): (Vector[String], Vector[String]) = {
    // locate windows service records
    println("\n\nRunning svcscan...\n\n")

    var svc = ""
    if(kdbg.nonEmpty){
      svc = {
        Try( s"python vol.py --conf-file=user_config.txt svcscan --verbose".!!.trim ).getOrElse("")
      }
    }else {
      svc = {
        Try( s"python vol.py -f $memFile --profile=$os svcscan --verbose".!!.trim ).getOrElse("")
      }
    }

    val svcLines = Source.fromString(svc).getLines.toVector
    val svcOneLine: ArrayBuffer[String] = svcParse(svcLines)

    /** If this list is not empty, it's likely that someone is using malicious services. */
    val stoppedSvc: Vector[String] = stoppedSvcs(svcOneLine)

    /** Need to grab */

    println("\n\nPrinting suspicious services that were stopped:\n\n")
    stoppedSvc.foreach(println)

    return (svcOneLine.toVector, stoppedSvc)
  } // END svcScan()

  /**
    * Combine each Service information entry to single line for each searching.
    *  When done, we can use mkString("|") to put our findings in readable format.
    */
  private[this] def svcParse(vec: Vector[String]): ArrayBuffer[String] = {
    var buff = ArrayBuffer[String]()
    var tempStr = ""

    var i = 0
    while (i < vec.size){
      if(vec(i).isEmpty){
        buff += tempStr
        tempStr = ""
      } // END if
      else{
        tempStr += (vec(i) + "|\n")

      } // END if/else

      i = i + 1
    } // END while loop

    return buff
  } // END svcParse()

  /** Finds suspicious services that an adversary potentially stopped */
  private[this] def stoppedSvcs(arr: ArrayBuffer[String]): Vector[String] = {

    /** A list of services that are suspicious if stopped. A lot could be added to list. AV vendors especially */
    val svcs = Vector("Wscsvc", "Wuauserv", "BITS", "WinDefend", "WerSvc")

    /** Find the services in the list above and then tell us if any of them were stopped */
    val foundSvcs: ArrayBuffer[String] = arr.filter(x => svcs.exists(y => x.contains(y)))
    val stoppedSvcs = foundSvcs.filter(x => x.contains("SERVICE_STOPPED"))

    /** Convert the services back to a readable format */
    val convertStopped = convertBack(stoppedSvcs)

    return convertStopped
  } // END stoppedSvcs()

  /** Convert svcscan back to a readable format. */
  // ArrayBuffer parameter should probably be an IndexedSeq
  private[this] def convertBack(arr: ArrayBuffer[String]): Vector[String]= {
    val splitBack = arr.map(x => x.split('|').mkString)
      .map(_.trim)
      .toVector
    return splitBack
  } // END convertBack()

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
/*
  private[this] def parseOutputDashEnv(volStr: String): Option[Vector[String]] = {
    val pattern = """=\w:\\\w+""".r
    Some(
      Source.fromString(volStr)
        .getLines
        .filterNot(_.contains("USERNAME"))
        .filterNot(_.contains("USERPROFILE"))
        .filterNot(_.contains("SESSIONNAME"))
        .filterNot(_.contains("USERDOMAIN"))
        .filterNot(x => pattern.findFirstIn(x).getOrElse("KillHackers") != "KillHackers")
        .dropWhile( !_.contains("------") )
        .dropWhile( _.contains("-----") )
        .map(_.trim)
        .toVector
    )
  } // END parseOutput()
  */
  /** Examines memory artifacts for commands run from the command prompt. */
  private[this] def consoles( memFile: String, os: String, kdbg: String ): (String, Vector[String]) = {

    /** This list of suspicious commands should be a lot longer!
      * Consider adding @FOR to look for use of scripting (it's a for loop)
      * Maybe also look for DO and @echo
      */

    // Looks for potentially suspicous commands that might give us insight into what was executed on command prompt.
    // FOR command should probably only return if found at the beginning of a line. (for and do will get false positives)
    val regString = ".*(net\\sview\\s|net\\suse\\s|net\\suser\\s|psexec\\s|smbclient\\s|wget\\s|do\\s|for\\s|" +
      "wmic\\s+process\\s+call\\s+create\\s|"+
      "netsh|curl\\s|sc\\s|reg\\s|enum\\s|cryptcat\\s|nc\\s|telnet\\s|at\\s|repair\\s|type\\s|backup\\s|nc\\.exe).*"
    val pattern = regString.r

    /*
    val cmdExplanation = Map("net view" -> "Provides information about SMB shares.",
    "at" -> "Used to create scheduled tasks on older versions of Windows",
    "wmi process call create" -> "Run a process from the commandline.",
    "start" -> "Start a process from the commandline (Windows XP and Server 2003)",
    "net use" -> "Establish SMB session from one Windows machine to another at a given IP address. With no args, allows user to see previous outbound SMB sessions.",
    "psexec" -> "Cause a target Windows machine to run a program.",
    "sc" -> "Remote service control",
    "reg" -> "Remote registry access",
    "enum" -> "Provide detailed information about SMB shares and systems. Like net view, but more detailed",
    "net view" -> "Provide information about SMB shares and systems.",
    "nc" -> "Can be used to establish a backdoor on a system. (and a lot of other non-malicious things)",
    "cryptcat" -> "Can be used to establish a backdoor on a system with encrypted communcation.",
    "telnet" -> "Can be used for both malicious and non-malicious purposes. It's generally a security risk.",
    "net user" -> "Pull all the domain users.",
    "type" -> "Used to create alternate data stream.",
    "smbclient" -> "Establish SMB session. Can be used to push or pull files from target.",
    "netsh" -> "Used for querying and changing networking settings. Can be used to disable firewall or learn the wifi password.",
    "for" -> "An indication that someone used a commandline for loop. Can be used for nefarious purposes.",
    "wget" -> "Used for web request. Can be used to access nefarious web server.",
    "curl" -> "Used for web request. Can be used to access nefarious web server.",
    "do" -> "Indication that someone was doing commandline scripting.")
    */

    println("\n\nRunning consoles scan...\n\n")

    var consoles = ""
    if(kdbg.nonEmpty){
      consoles = Try( s"python vol.py --conf-file=user_config.txt consoles".!!.trim ).getOrElse("")
    }else {
      consoles = Try(s"python vol.py -f $memFile --profile=$os consoles".!!.trim).getOrElse("")
    }

    println("\n\nPrinting consoles scan...\n")
    println(consoles)

    val consolesString = consoles.toLowerCase
    val consolesScan = parseConsoles( consolesString ).getOrElse( Vector[String]() )

    /** Contains any of the above commands */
    val suspiciousCMDs: Vector[String] = consolesScan.map(x => pattern.findFirstIn(x)).map(x => x.getOrElse(""))

    return (consolesString, suspiciousCMDs)
    /** Operations on consoles. */
  } // END run()

  private[this] def parseConsoles(volStr: String): Option[Vector[String]] = {
    Some( Source.fromString(volStr)
      .getLines
      .dropWhile( !_.contains("Output:") )
      .map(_.trim)
      .toVector
    )
  } // END parseConsoles()

} // END SysStateScan object

/********************************** RootkitDetector Object ****************************/
case class RootkitResults( callbacks:(Vector[String], Vector[String]),
                           hiddenModules: (Vector[String], String),
                           timers: Vector[String],
                           deviceTree: String,
                           orpanThread: String,
                           ssdtFound: Boolean = false)

object RootkitDetector extends VolParse {

  /**
    * run()
    * The functional main method
    * @param memFile
    * @param os
    */
  private[windows] def run(memFile: String, os: String, kdbg: String): RootkitResults = {

    /** Returns hidden modules found and result of modscan - (hiddenModules, modscanResults) */
    val hiddenModules: (Vector[String], String) = findHiddenModules(memFile, os, kdbg)

    if(hiddenModules._1.nonEmpty) println("Printing hidden modules:\n")
    hiddenModules._1.foreach(println)
    println("Printing modscan results:\n")
    println(hiddenModules._2)

    /** Returns tuple w/ Unknown Kernel Modules and calls to APIs commonly used by rootkits */
    val callbacks: (Vector[String], Vector[String]) = callbackScan(memFile, os, kdbg)

    println("\nPrinting unknown kernel Modules if found:\n")
    if(callbacks._1.isEmpty){
      println("No unknown kernel modules found...\n\n")
    } else{
      callbacks._1.foreach(println)
    }
    if(callbacks._2.isEmpty){
      println("No APIs commonly used by rootkits were found on system\n\n")
    }else{
      println("The following calls to APIs commonly used by rootkits were found:\n\n")
      callbacks._2.foreach(println)
    }

    /** Returns Vector of information about timers to unknown modules */

    val timers: Vector[String] = timerScan(memFile, os, kdbg)
    if(timers.nonEmpty) println("\nPrinting information about timers to unknown modules:\n\n")
    timers.foreach(println)

    val deviceTree: String = deviceTreeScan(memFile, os, kdbg)
    // println("Device Tree Scan Complete...\n\n")
    // println(deviceTree)

    val thread: String = threadScan(memFile, os, kdbg)
    if(thread.nonEmpty) println("\nPrinting orphaned threads...\n\n")
    println(thread)

    var ssdt = false
    if(os.contains("x86")){
      ssdt = ssdtScan(memFile, os, kdbg)
    }


    /************************************
      * NEED TO PERFORM SSDT scan
      ***********************************/
    // return RootkitResults(callbacks, hiddenModules, timers, deviceTree, thread)
    return RootkitResults(callbacks, hiddenModules, timers, deviceTree, thread, ssdt)
  } // END run()

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

  private[this] def threadScan(memFile: String, os: String, kdbg: String): String = {

    var orphanThreadScan = ""
    if(kdbg.nonEmpty){
      orphanThreadScan = {
        Try( s"python vol.py --conf-file=user_config.txt threads -F OrphanThread".!!.trim )
          .getOrElse("An error occurred while performing OrpanThread scan...")
      }
    }else{
      /** Look for orphan threads 379-380 */
      orphanThreadScan = {
        Try( s"python vol.py -f $memFile --profile=$os threads -F OrphanThread".!!.trim )
          .getOrElse("An error occurred while performing OrpanThread scan...")
      }
    }

    /************************************
      * THIS COULD BE SPLIT on "------"
      ***********************************/

    return orphanThreadScan
  } // END threadScan()

  /**
    * findHiddenModules()
    * Looks for hidden kernel modules
    * @param memFile
    * @param os
    * @return (Vector[String], Vector[String]) - (hiddenModules, completeModScan)
    */
  private[this] def findHiddenModules(memFile: String, os: String, kdbg: String): (Vector[String], String) = {

    /** Look for loaded modules */
    val modules = modulesScan(memFile, os, kdbg)
    /** modscan contains hidden modules (_.1 = full scan, _.2 = names of modules) */
    val modScanResult: (String, Vector[String]) = modScan(memFile, os, kdbg)
    /** Look for unloaded modules */
    val unloadedModules: Vector[String] = unloadedModulesScan(memFile, os, kdbg)

    /** Creates a Vector of both unloaded and loaded modules in Uppercase */
    val allModules: Vector[String] = modules.map( _.toUpperCase() ) ++: unloadedModules.map( _.toUpperCase() )

    /** Contains a vector of all the hidden kernel module names */
    val hiddenModules: Vector[String] = modScanResult._2.map(_.toUpperCase()).intersect(allModules)

    /** Returns tuple with hidden modules discovered and the results of modScan */
    return (hiddenModules, modScanResult._1)
  } // END findHiddenModules()

  /**
    * modulesScan()
    * Do modules scan and parse results to find names
    * @param memFile
    * @param os
    * @return
    */
  private[this] def modulesScan(memFile: String, os: String, kdbg: String): Vector[String] = {

    var modulesScan = ""
    if(kdbg.nonEmpty){
      modulesScan = Try( s"python vol.py --conf-file=user_config.txt modules".!!.trim ).getOrElse("")
    }else{
      modulesScan = Try( s"python vol.py -f $memFile --profile=$os modules".!!.trim ).getOrElse("")
    }

    val modules: Option[Vector[String]] = parseOutputDashVec(modulesScan)
    val modulesParsed: Vector[Vector[String]] = {
      vecParse(modules.getOrElse(Vector[String]())).getOrElse(Vector[Vector[String]]())
    }
    /** Grab column 1 */
    val moduleNames = modulesParsed(1)

    /** Returns vector of module names */
    return moduleNames
  } // END modulesScan()

  /**
    * modScan()
    * Use modscan module and parse results to find names
    * @param memFile
    * @param os
    * @return
    */
  private[this] def modScan(memFile: String, os: String, kdbg: String): (String, Vector[String]) = {

    /** I'd really like this scan to return the results of it's general scan also! */

     var modScan = ""
      if(kdbg.nonEmpty){
        modScan = Try( s"python vol.py --conf-file=user_config.txt modscan".!!.trim ).getOrElse("")
      }else{
        modScan = Try( s"python vol.py -f $memFile --profile=$os modscan".!!.trim ).getOrElse("")
      }


    val modules: Option[Vector[String]] = parseOutputDashVec(modScan)
    val modulesParsed: Vector[Vector[String]] = {
      vecParse(modules.getOrElse(Vector[String]())).getOrElse(Vector[Vector[String]]())
    }

    val moduleNames: Vector[String] = modulesParsed(1)

    /** Returns tuple with vector of modscan results and module names */
    return (modScan, moduleNames)
  } // END modScan()

  /**
    * unloadedModulesScan()
    * Do unloadedmodules scan and parse results to return name
    * @param memFile
    * @param os
    * @return
    */
  private[this] def unloadedModulesScan(memFile: String, os: String, kdbg: String): Vector[String] = {

    // Regex to grab the module name
    val unloadedRegex = "\\w+".r

    var unloadedModScan = ""
    if(kdbg.nonEmpty){
      unloadedModScan = {
        Try( s"python vol.py --conf-file=user_config.txt unloadedmodules".!!.trim ).getOrElse("")
      }
    }else{
      unloadedModScan = {
        Try( s"python vol.py -f $memFile --profile=$os unloadedmodules".!!.trim ).getOrElse("")
      }
    }

    val unloadedModules = parseOutputVec( unloadedModScan )

    val unloadedNames = unloadedModules.getOrElse(Vector[String]() ).map(x => unloadedRegex.findFirstIn(x))

    /** Returns Vector of unloaded module names */
    return unloadedNames.map(x => x.getOrElse(""))
  } // END unloadedModulesScan()

  /**
    * timerScan()
    * Perform timers scan and look for kernel timers to unknown modules
    * @param memFile
    * @param os
    * @return
    */
  private[this] def timerScan(memFile: String, os: String, kdbg: String): Vector[String] = {

    /** Do this scan before doing the callback scan and driverscan */

    var timerScan = ""
    if(kdbg.nonEmpty){
      /** Look for kernel timers */
      timerScan = {
        Try( s"python vol.py --conf-file=user_config.txt timers".!!.trim ).getOrElse("")
      }
    }else{
      /** Look for kernel timers */
      timerScan = {
        Try( s"python vol.py -f $memFile --profile=$os timers".!!.trim ).getOrElse("")
      }
    }


    // Might need to make this toUpperCase()
    val timer = parseOutputDashVec( timerScan )

    // Find kernel timers to uknown modules
    val unknownTimers = timer.filter(_.contains("UNKNOWN"))

    /** Returns scan results that include timers to unknown modules */
    return unknownTimers.getOrElse(Vector[String]())
  } // END timerScan()

  /**
    * callbackScan()
    * Looks for Unknown modules and occurences of certain API calls commonly used by rootkits
    * @param memFile
    * @param os
    * @return (unknownModules, callbacks involving significant API calls)
    */
  private[this] def callbackScan(memFile: String, os: String, kdbg: String): (Vector[String], Vector[String]) = {

    // Stores API calls we want to look for
    val apiCalls = Vector( "PsSetCreateProcessBbsNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
      "PsSetLoadImageNotifyRoutine", "IoRegisterShutdownNotification", "IoRegisterFsRegistrationChange",
      "DbgSetDebugPrintCallback", "CmRegisterCallback", "CmRegisterCallbackEx", "IoRegisterPlugPlayNotification",
      "KeRegisterBugCheckCallback", "KeRegisterBugCheckReasonCallback" )

    /** It will be a problem if any if any of the api calls get snipped. Consider shortening */

    var callbackScan = ""
    if(kdbg.nonEmpty){
      callbackScan = {
        Try( s"python vol.py --conf-file=user_config.txt callbacks".!!.trim ).getOrElse("")
      }
    }else{
      callbackScan = {
        Try( s"python vol.py -f $memFile --profile=$os callbacks".!!.trim ).getOrElse("")
      }
    }
    /** Perform callback scan */

    val callbackParsed = parseOutputDashVec(callbackScan)

    /** Look for unknown modules. It's likely we don't have to perform the toUpperCase transformation */
    val unknownModules = callbackParsed.getOrElse(Vector[String]())
      .map(_.toUpperCase)
      .filter(_.contains("UNKNOWN"))

    /** Look through callback scan results and find api calls of interest */
    val callbacks = callbackParsed.getOrElse(Vector[String]())
      .map(_.toUpperCase())
      .filter(x => apiCalls.exists(y => apiCalls.map( _.toUpperCase() ).contains(x)))

    // Might want to create a map w/ explanations of what the api calls do. (396)
    // We need to tell the user which modules are calling which APIs.
    // It would be helpful to find a list of kernel modules that are standard on clean systems.

    /** The unknown modules are the most important, but the calls to certain APIs warrant futher investigation */
    return (unknownModules, callbacks)
  } // callbackScan()

  private[this] def driverScan(memFile: String, os: String, kdbg: String): String = {

    var driverScan = ""
    if(kdbg.nonEmpty){
      /** See notes and 382-383 for information about processing driver scans */
      driverScan = {
        Try( s"python vol.py --conf-file=user_config.txt driverscan".!!.trim ).getOrElse("")
      }
    }else {
      /** See notes and 382-383 for information about processing driver scans */
      driverScan = {
        Try( s"python vol.py -f $memFile --profile=$os driverscan".!!.trim ).getOrElse("")
      }
    }

    return driverScan
    // Re-read Stealthy Hooks section and consider writing python plugin

  } // END driverScan()

  private[this] def ssdtScan(memFile: String, os: String, kdbg: String): Boolean = {
    var inlineHookFound = false
    var ssdt = ""
    if(kdbg.nonEmpty){
      ssdt = {
        Try( s"python vol.py --conf-file=user_config.txt ssdt --verbose".!!.trim ).getOrElse("")
      }
    }else{
      ssdt = {
        Try( s"python vol.py -f $memFile --profile=$os ssdt --verbose".!!.trim ).getOrElse("")
      }
    }

    val ssdtParsed = parseOutputNoTrim(ssdt).getOrElse(Vector[String]())
    val inlineHook = ssdtParsed.filter(x => x.contains("HOOK?")).filter(x => x.contains("UNKNOWN"))

    var buff = ArrayBuffer[String]()
    var i = 0
    while(i < ssdtParsed.length){
      if(ssdtParsed(i).contains("HOOK?") & ssdtParsed(i).contains("(UNKNOWN)")){

        /** Grab address locations */
        val regex = "\\w+".r
        val splitPreviousLine = ssdtParsed(i-1).split(':')
        val splitCurrent = ssdtParsed(i).split('>')
        val firstAddress = regex.findFirstIn(splitPreviousLine(1)).getOrElse("no")
        val secondAddress = regex.findFirstIn(splitCurrent(1)).getOrElse("Word")
        /** Check if address locations are the same. */
        if(firstAddress != secondAddress){
          println("Inline Hook Rootkit Found")
          inlineHookFound = true
        }

      } // END if
      i = i + 1
    } // END while

    // Need to check the pointer value

    // Need to make sure to include previous line so we can see which driver is calling it.
    return inlineHookFound
  }// END ssdt()
  /** Detect hidden network activity*/
  private[this] def driverIrpScan(memFile: String, os: String, kdbg: String) = {

    var driverIrpScan = ""
    if(kdbg.nonEmpty){
      driverIrpScan = {
        Try( s"python vol.py --conf-file=user_config.txt driverirp -r tcpip".!!.trim ).getOrElse("")
      }
    }else{
      driverIrpScan = {
        Try( s"python vol.py -f $memFile --profile=$os driverirp -r tcpip".!!.trim ).getOrElse("")
      }
    }

    /** See notes and 382-383 for information about processing driver scans */

    val parsed = parseOutputDashVec(driverIrpScan).getOrElse(Vector[String]())
    // regex to grab driver name.
    val regex = "(\\|\\.|\\w+)$".r

    val filterDriverNames = parsed.filterNot(x => regex.findFirstIn(x).getOrElse("Boo") == "Boo")

    val suspectDrivers = filterDriverNames.filterNot(x => x.contains("tcpip.sys"))
      .filterNot(x => x.contains("ntoskrnl.sys"))

    /**
      * Should point to a regular system driver. What are normal system drivers?
      */
  } // END driverIrpScan()

} // END RootkitDetector Object

/********************************** RemoteMappedDriveSearch *********************************/
object RemoteMappedDriveSearch extends VolParse {
  private[windows] def run( memFile: String, os: String, kdbg: String ): Vector[(String, String)] = {

    println("\nSearching for Remote Mapped Drives... \n")
    remoteMapped(memFile, os, kdbg)

  } // END run()

  /**
    * remoteMapped()
    * Search for remote mapped drives
    * @param memFile memory dump
    * @param os os
    * @return Vector(String, String) (pid -> Remote Mapped Info)
    */
  private[this] def remoteMapped(memFile: String, os: String, kdbg: String): Vector[(String, String)] = {
    var remoteMapped = ""
    if (kdbg.nonEmpty) {
      remoteMapped = {
        Try(s"python vol.py --conf-file=user_config.txt handles -t File, Mutant".!!.trim).getOrElse("")
      }
    } else {
      remoteMapped = Try(s"python vol.py -f $memFile --profile=$os handles -t File, Mutant".!!.trim).getOrElse("")
    }

    val remoteSearchLines: Option[Vector[String]] = parseOutputNoHeader(remoteMapped)

    val remoteMapFilter: Vector[String] = remoteSearchLines.getOrElse(Vector[String]())
      .filter(_.contains("Mup\\;"))

    val lanman: Vector[String] = remoteSearchLines.getOrElse(Vector[String]())
      .filter(_.contains("LanmanRedirector\\;"))
    val combineMappedDrive: Vector[String] = remoteMapFilter ++: lanman

    // val foundMapped = combineMappedDrive.filter(_.contains(";"))

    val remote2d: Vector[Vector[String]] = vecParse(combineMappedDrive).getOrElse(Vector[Vector[String]]())

    val remoteTup: Vector[(String, String)] = remote2d.map(x => (x(1), x(5)))

    println("\nPrinting Remote Mapped Drive Values\n")
    remoteTup.foreach(println)

    return remoteTup
  }
/*
    // Pattern looks for Device\Mup\;[A-Z]:\w+
    val mupPattern = "(?<=\\w+Mup\\)[;][a-zA-Z]+".r
    val lanmanPattern = "(?<=\\w+LanmanRedirector\\)[;][a-zA-Z]+".r

    /** Contains remote drive name/netbios name/share or file system path name */
    val remoteMupFindings: Vector[String] = {
      remoteMup.filter(x => mupPattern.findFirstIn(x).getOrElse("I_believe_in") != "I_believe_in")
    }

    val remoteLanmanFindings: Vector[String] = {
      remoteLanman.filter(x => lanmanPattern.findFirstIn(x)
        .getOrElse("leaders_with_consciences") != "leaders_with_consciences")
    }

    // Locate the PIDs for each of the remote mapped devices found.
    // Probably need to use a case statement to test if any of the items are empty.
    val regPID = "(?<=\\w+\\s)\\d+".r
    val getLanmanPID: Vector[String] = remoteLanmanFindings.map(x => regPID.findFirstIn(x).getOrElse(""))
    val getMupPID: Vector[String] = remoteMupFindings.map(x => regPID.findFirstIn(x).getOrElse(""))

    /** Contains the PIDs for all of the remote mapped devices */
    val pids: Vector[String] = getLanmanPID ++: getMupPID

    /** Contains all of the remote mapped device findings */
    val remoteMappedResults = remoteMupFindings ++: remoteLanmanFindings

    val zipped: Vector[(String, String)]= pids.zip(remoteMappedResults)

    val remoteMappedDict: Map[String, String] = zipped.toMap

    return remoteMappedDict
    */
   // END remoteMapped()

  /** Skipping symlinkscan for now because it's unnecessary */
/*
  /**
    * symLinkScan()
    * Used to find when a symbolic link was created (remote mapped drive)
    * @param memFile memory dump
    * @param os os
    * @return mutable.Map[String, String]
    *         map contains path to remote mapped drive -> timestamp when created
    */
  def symLinkScan(memFile: String, os: String): mutable.Map[String, String] = {

    /** Need to grab the "Creation Time" and the "From" columns */
    val symLinkScan = Some( s"python vol.py -f $memFile --profile=$os symlinkscan" )
    val symParsed = parseOutputDashVec(symLinkScan.getOrElse(""))

    /** Stores Time Created */
    val timePattern = """(?<=\w+\s\d+\s\d+\s)\w+\s\w+\s\w+""".r
    val symLinkPattern = """(?<=\w+\s\d+\s\d+\s\w+\s\w+\s\w+)\w+""".r

    val timeResult = {
      symParsed.getOrElse(Vector[String]()).map(x => timePattern.findFirstIn(x))
    }
    val symLinkResult: Vector[Option[String]] = {
      symParsed.getOrElse(Vector[String]()).map(x => symLinkPattern.findFirstIn(x))
    }
    val map = mutable.Map[String, String]()


    var i = 0
    while(i < timeResult.length){
      map += (symLinkResult(i).getOrElse("") -> timeResult(i).getOrElse(""))
      i = i + 1
    }

    return map
  } // symLinkScan()
*/
} // END RemoteMappedDriveSearch object
