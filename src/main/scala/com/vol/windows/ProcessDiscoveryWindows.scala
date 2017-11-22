package com.bbs.vol.windows

import java.math.BigInteger

import StringOperations._
import com.bbs.vol.utils.SearchRange

/**
  * Main Class: ProcessDiscoveryWindows
  * Purpose: Examine each process in detail and find out as much as possible about it.
  *
  * Also in File:
  * AutomateYara object
  * DetectRegPersistence object
  * DetectUnlinkedDLLs object
  */

import scala.collection.mutable
import scala.collection.mutable.ArrayBuffer
import sys.process._
import scala.io.Source
import scala.util.Try

/** This is the class that run() will return. Obviously the types need to be changed. */
/** MUST RETURN
  * malfind
  * yaraScan
  * parents
  * dllInfo
  * ldrInfo
  * regPersistenceInfo
  * enabledPrivs
  */
final case class ProcessBrain( yara: YaraBrain,
                               regPersistence: Vector[RegPersistenceInfo],
                               dllInfo: Vector[DllInfo],
                               ldrInfo: Vector[LdrInfo],
                               // fileDiscrep: String,
                               // parents: Vector[(String, Vector[(String, String)])],
                               privs: Vector[Privileges],
                               malfind: Map[String, String],
                               netActivity: Map[String, Boolean],
                               promiscMode: Map[String, Boolean]) // Map of PID -> (whether or not proc does networking)

/** Stores pertinent information parsed from yarascan */
final case class YaraParse( classification: String, // What list did rule come from?
                            rule: String,           // What rule was matched?
                            owner: String,          // Which PID and process was matched?
                            offset: String ) {      // Where in memory was the match found?
  override def toString( ): String = {
    "\nClassification: " + classification + "\nRule: " + rule + "\n" + owner + "\nOffset: " + offset + "\n"
  } // END toString()

} // END case class YaraParse

final case class YaraBrain( url: Vector[YaraParseString],     // URLs present in process memory.
                            ip: Vector[YaraParseString],      // IPs present in process memory.
                            malware: Vector[YaraParseString], // Malware indicators found in process memory.
                            suspItems: YaraSuspicious,        // antidebug, exploitkits, webshells, cve,
                                                              // malicious documents, suspicious strings.
                            crypto: Vector[YaraParse],        // Cryptography signatures found in process memory.
                            dllInHexRange: ArrayBuffer[ArrayBuffer[String]])

final case class DllHexInfo(pid: String, dllName: String, lowHex: Long, highHex: Long){
  override def toString = "pid: " + pid + " dll name: " + dllName + " low hex: " + lowHex + " high hex: " + highHex
} // END case class DLLHexInof

/** Case class used if we want to include data found in String column of yarascan. */
final case class YaraParseString(rule: String, proc: String, str: String) {
  override def toString = "\nRule: " + rule + "\n" + proc + "\nData Found:" + str + "\n"
} // END case class YaraParseString

/** Stores information we find out about the privileges each PID has. */
case class Privileges( pid: String,
                       debugPriv: Boolean,
                       enabledPrivs: ArrayBuffer[String],
                       suspiciousPrivs: ArrayBuffer[String] ){
  override def toString: String = {
    "PID: " + pid + "\nDebug Enabled: " + debugPriv + "\nEnabled: " + enabledPrivs.mkString + "\nSuspicious: " + suspiciousPrivs.mkString
  }
} // END Privileges class

/**
  * IDEA: CLASSIFY each process after examination.
  * For Example: Is the process involved in network activity and what kind of activity?
  * One was to determine this is by looking at the types of DLLs that are linked to the process.
  *
  * EXTENDED IDEA: CLASSIFY normal processes
  * For Example: A lot of processes shouldn't be involved with network activity.
  * Generate a list of processes that shouldn't be doing certain things.
  */

object ProcessDiscoveryWindows extends VolParse {

  /****************************************************
    ***************************************************
    ******************~~~~~RUN~~~~*********************
    ***************************************************
    ***************************************************/

  private[windows] def run(memFile: String, os: String, kdbg: String, process: Vector[ProcessBbs], netConn: Vector[NetConnections]): ProcessBrain = {

    /**
      * LOGIC NEEDS TO BE DIFFERENT NOW THAT WE'RE LOOKING AT OFFSETS.
      */

    /** Need to reorganize the data */
    val (dllInfo, ldrInfo): (Vector[DllInfo], Vector[LdrInfo]) = DllScan.run(os, memFile, kdbg, process)
    println("\n\nPrint DLL Info: \n\n")
    dllInfo.foreach(println)
    // println("\n\nPrint LDR Info: \n\n")
    // ldrInfo.foreach(println)

    /**
      * NEED TO PASS Vector[DllInfo] to yarascan
      */

    /** Perform all yarascans*/
    println("\n\nScanning memory with yara...\n\n")
    val yaraScan: YaraBrain = AutomateYara.run(os, memFile, kdbg, process, netConn, dllInfo)

    /** Determine all parents that a process inherits from. */
    // val parents: Vector[(String, Vector[(String, String)])] = for(pid <- pidVec) yield getParents(pid, process)

    // val test: Vector[Vector[(String, String)]] = for(parent<- parents) yield parent._2

    /* Test if the logic works. */
    /*
    println("\n\nPrint Parents")
    for{
      value <- test
      result <- value
    } println( "\n\nPID: " + result._2 + "\nParents: " + result._2)
*/
    println("\n\nScanning to determine if an attacker established registry persistence...\n\n")

    /** Used to detect registry persistence. Contains Strings from the individual scans pg. 183*/
    val regPersistenceInfo: Vector[RegPersistenceInfo] = {
      for(proc <- process) yield DetectRegPersistence.run(memFile, os, kdbg, proc.pid, proc.offset, proc.hidden)
    } // END regPersistenceInfo
    println("\n\nPrint registry persistence info: \n\n")
    regPersistenceInfo.foreach(println)

    println("\n\nScanning to determine process networking capabilities...\n\n")

    /** Determine which pids have networking capability and look for promiscuous mode. */
    val (netPidMap, promiscMap): (Map[String, Boolean], Map[String, Boolean]) = {
      examineNetActivity(memFile, os, kdbg)
    }

    /********************************************
      * THIS IS CAUSING PROBLEMS WITH OLDER OSs
      *******************************************/
    println("\n\nPrinting information about pid's networking capability...\n\n")
    for((key, bool) <- netPidMap) println(key + " -> " + bool )
    println("\n\nPrinting information about promiscuous mode...\n\n")
    for((key, bool) <- promiscMap)println(key + " -> " + bool)

    println("\n\nScanning for explicitly enabled privileges...\n\n")

    /** Only gives privileges that a process specifically enabled. */
    val enabledPrivs: Vector[Privileges] = {
      for (proc <- process) yield findEnabledPrivs(memFile, os, kdbg, proc.pid, proc.offset, proc.hidden)
    }
    enabledPrivs.foreach(println)

    /** Perform malfind scan*/
    val malfind: Map[String, String] = malfindScan(memFile, os, kdbg, process)

    println("\n\nPrinting malfind results...\n\n")
    for((key, scan) <- malfind) println(key + "\n" + scan)

/**
  * Looks for artifacts of network sockets that the process created.
  * Currently this method returns the entire scan result if network artifacts are found.
  * Method might be unnecessary
  */
    return ProcessBrain(yaraScan, regPersistenceInfo, dllInfo, ldrInfo, enabledPrivs, malfind, netPidMap, promiscMap )
  } // END run()

  /**********************************************************************/
  /****************************** END RUN *******************************/
  /**********************************************************************/

  /**
    * HELPER METHODS
    */

  /**
    * getParents()
    * Figure out who all the parents of a process are.
    * Return tuple (pid -> Vector[(ppid, process name)])
    * I know I should use recursion, but I'm lazy.
    */

  /**********************************************************************
   ***** FIX THIS!! Use recursion!!
   **********************************************************************/

  private[this] def getParents(pid: String, pids: Vector[ProcessBbs]): (String, Vector[(String, String)]) = {
    /** Returns the ppid of pid as the first value in Vector */
    val directParent = for {
      pidVal <- pids
      if pidVal.pid == pid
    } yield (pidVal.ppid, pidVal.name)
    val parentParent = for{
      pidVal <- pids
      if directParent.nonEmpty
      if pidVal.pid == directParent(0)._1
    } yield (pidVal.ppid, pidVal.name)
    val parent3 = for{
      pidVal <- pids
      if parentParent.nonEmpty
      if pidVal.pid == parentParent(0)._1
    } yield (pidVal.ppid, pidVal.name)
    val parent4 = for{
      pidVal <- pids
      if parent3.nonEmpty
      if pidVal.pid == parent3(0)._1
    } yield (pidVal.ppid, pidVal.name)
    val parent5 = for{
      pidVal <- pids
      if parent4.nonEmpty
      if pidVal.pid == parent4(0)._1
    } yield (pidVal.ppid, pidVal.name)
    val parent6 = for{
      pidVal <- pids
      if parent5.nonEmpty
      if pidVal.pid == parent5(0)._1
    } yield (pidVal.ppid, pidVal.name)
    val parent7 = for{
      pidVal <- pids
      if parent5.nonEmpty
      if pidVal.pid == parent6(0)._1
    } yield (pidVal.ppid, pidVal.name)

    var buff = ArrayBuffer[(String, String)]()

    /** if a parent exists, add it to the ArrayBuffer */
    if(directParent.nonEmpty) buff ++= directParent
    if(parentParent.nonEmpty) buff ++= parentParent
    if(parent3.nonEmpty) buff ++= parent3
    if(parent4.nonEmpty) buff ++= parent4
    if(parent5.nonEmpty) buff ++= parent5
    if(parent6.nonEmpty) buff ++= parent6
    if(parent7.nonEmpty) buff ++= parent7

    return (pid, buff.toVector)
  } // END getParents()

  /** Scan with malfind for all processes. */
  private[this] def malfindScan(memFile: String, os: String, kdbg: String, process: Vector[ProcessBbs]): Map[String, String] = {
    val resultVec: Vector[(String, String)] = {
      for(proc <- process) yield malfindPerPid(memFile, os, kdbg, proc.pid, proc.offset, proc.hidden)
    }
    return resultVec.toMap
  } // END malfind()

  /** Scan with malfind for each individual process. */
  private[this] def malfindPerPid(memFile: String, os: String, kdbg: String, pid: String,
                                  offset: String, hid: Boolean): (String, String) = {
    var malScan = ""
    if(kdbg.nonEmpty){
      if (hid)
        malScan = Try( s"python vol.py --conf-file=user_config.txt --offset=$offset".!!.trim).getOrElse("")
      else
        malScan = Try( s"python vol.py -f $memFile --profile=$os malfind -p $pid".!!.trim).getOrElse("")
    } // END if kdbg.nonEmpty()



    return (pid, malScan)
  } // END malfindPerPid()

  /** Determines which PIDs do networking and if promiscuous mode is on. */
  private[this] def examineNetActivity(memFile: String, os: String, kdbg: String): (Map[String, Boolean], Map[String, Boolean]) = {
    var networkActivity = ""
    if(kdbg.nonEmpty){
      networkActivity = Try( s"python vol.py --conf-file=user_config.txt handles -t File").getOrElse("")
    }else{
      networkActivity = Try( s"python vol.py -f $memFile --profile=$os handles -t File").getOrElse("")
    }
    networkActivity = Try( s"python vol.py -f $memFile --profile=$os handles -t File").getOrElse("")
    val netActivityVec: Vector[String] = parseOutputNoHeader(networkActivity).getOrElse(Vector[String]())
    val netActivity = netCheck(netActivityVec)
    val promiscMode = promiscCheck(netActivityVec)

    return (netActivity, promiscMode)
  } // END examineNetActivity()

  /** Determines if an individual PID does networking */
  private[this] def netCheck(vec: Vector[String]): Map[String, Boolean] = {
    val netActivity = vec.filter(x => x.contains("Afd\\Endpoint"))

    val netActivity2d = vecParse(netActivity).getOrElse(Vector[Vector[String]]())

    val pidToActivity: Vector[(String, Boolean)] = netActivity2d.map(x => (Try(x(1)).getOrElse("problem"), true))

    return pidToActivity.toMap
  } // END netPerPid()

  /** Looks for promiscuous mode */
  private[this] def promiscCheck(vec: Vector[String]): Map[String, Boolean] = {
    val netActivity = vec.filter(x => x.contains("RawIp\\0"))
    val netActivity2d = vecParse(netActivity).getOrElse(Vector[Vector[String]]())

    val pidToActivity: Vector[(String, Boolean)] = netActivity2d.map(x => (Try(x(1)).getOrElse("problem"), true))

    return pidToActivity.toMap
  } // END promiscCheck()

  /**
    * fileNameDiscrepancies()
    * Looks for artifacts of network sockets that the process created.
    * Currently this method returns the entire scan result if network artifacts are found.
    * @param memFile
    * @param os
    * @param pid
    * @return Vector[String]
    */
  private[this] def fileNameDiscrepancies(memFile: String, os: String, kdbg: String, pid: String): Vector[String] = {

    println("\n\nSearching for filename discrepancies...\n\n")

    var fileNameDiscrep = ""
    if(kdbg.nonEmpty){
      fileNameDiscrep = {
        Try( s"python vol.py -f $memFile --conf-file=user_config.txt -t File, Mutant --silent".!!.trim )
          .getOrElse("")
      }
    }else{
      fileNameDiscrep = {
        Try( s"python vol.py -f $memFile --profile=$os -p $pid handles -t File, Mutant --silent".!!.trim )
          .getOrElse("")
      }
    }

    /** Make sure the filenames in the details and the filenames for each process match (182) */
    val pattern = ".*(NamedPipe|Tcp|Ip).*".r
    val parsedDiscrepancies = parseOutputDashVec(fileNameDiscrep)
    val lookForDiscrepancies = {
      parsedDiscrepancies.getOrElse(Vector[String]())
        .map(x => pattern.findFirstIn(x).getOrElse("where's the line?") != "where's the line?")
    }
    println("Printing filename discrepancies:\n\n")
    lookForDiscrepancies.foreach(println)

    // Look for named "NamedPipe", "\Device\Tcp", and "\Device\Ip"
    // If there are occurrences, we should print full result.
    // See page 182-183 for more info.
    // Doing a thorough analysis of handles will require a lot of research.
    // NOTE: It might be useful to consider the size of the handle count.

    if(lookForDiscrepancies.nonEmpty){
      parsedDiscrepancies.getOrElse(Vector[String]())
    }else {
      Vector[String]()
    } // END if/else

  } // END fileNameDiscrepancies()

  /**
    * findEnabledPrivs()
    * Looks for suspicious privileges that a process enabled.
    * When the results of this print, tell the user to compare the privs ot process explorer.
    * @param memFile
    * @param os
    * @param pid
    * @return (ArrayBuffer of all privs enabled, ArrayBuffer of suspicious privs enabled)
    */
  def findEnabledPrivs(memFile: String, os: String, kdbg: String, pid: String, offset: String, hid: Boolean): Privileges ={

    // Need to research more privileges to add to this list.

    // println("\n\nSearching for explicitly enabled privileges...\n\n")

    /** Contains Vector of privileges that could be significant if enabled.*/
    val significantPrivs: Vector[String] = Vector( "SeDebugPrivilege", "SeLoadDrivePrivilege", "SeBackupPrivilege",
      "SeLoadDriverPrivilege", "SeChangeNotifyPrivilege", "SeShutdownPrivilege" )

    // There are a lot of other privileges that should probably be added to the list.
    var privsScan = ""
    /** Allows us to determine which privilege the process enabled (list on 171-172) */
    if(kdbg.nonEmpty){
      if (hid)
        privsScan = Try( s"python vol.py --conf-file=user_config.txt --offset=$offset".!!.trim ).getOrElse("")
      else
        privsScan = Try( s"python vol.py --conf-file=user_config.txt privs -p $pid".!!.trim ).getOrElse("")
    }else{
      if (hid)
        privsScan = Try( s"python vol.py -f $memFile --profile=$os privs --offset=$offset".!!.trim ).getOrElse("")
      else
        privsScan = Try( s"python vol.py -f $memFile --profile=$os privs -p $pid".!!.trim ).getOrElse("")
    }


    /** Only gives privileges that a process specifically enabled by process. */
    val privs: Option[Vector[String]] = parseOutputDashVec( privsScan )
      .filter( _.contains("Enabled") )
      .filterNot( _.contains("Default") )

    /** Figure out if SeDebugPrivilege is enabled and store in tuple w/ PID */
    val debugEnabled: Vector[Boolean] = Some({
      privs.getOrElse(Vector[String]())
        .map( _.toUpperCase() )
        .map( x => x.contains("SEDEBUGPRIVILEGE") )
        }).getOrElse(Vector[Boolean]())

    val debugBool = if(debugEnabled.isEmpty) false else true

    /** This could be replaced by lookahead regex */
    val privsWithColumns: Vector[Vector[String]] = {
      vecParse( privs.getOrElse( Vector[String]()) ).getOrElse( Vector[Vector[String]]() )
    }
    // val privsWithColumns: Vector[Vector[String]] = vecParse( privsParse ).getOrElse(Vector[Vector[String]]())

    /** Creates an ArrayBuffer of the privileges the process created */
    val enabledPrivsBuff = ArrayBuffer[Option[String]]()
    var i = 0
    // might need to use (privsWithColumns.length - 1) hopefully trim will fix it.
    while(i < privsWithColumns.length) {
      enabledPrivsBuff += Some(privsWithColumns(i)(4))
      i += 1
    } // END while

    val enabledPrivs = enabledPrivsBuff.map(x => x.getOrElse(""))

    /** If any suspicious privileges were enabled by a process, they are stored in this ArrayBuffer */
    val suspiciousPrivs: ArrayBuffer[String] = {
      enabledPrivs.filter(x => significantPrivs.exists(y => x.contains(y)))
    }

    // Need another methods that looks for privs based on the executable
    // Example: Look for SeDebugPrivilege and SeLoadDriverPrivilege in explorer.exe
    // We can get a list of correct privs enabled by different processes by parsing output on clean system.

    /** NOTE: We don't really need to use the command below, but might be easier than manually parsing.
      * Count the times that Enabled occurs.
      * IGNORE UNDOCK PRIV: explorer.exe always enables undock priv. */

    return Privileges(pid, debugBool, enabledPrivs, suspiciousPrivs)
  } // END findEnabledPrivs()

} // END ProcessDiscoveryWindows class

/**
  * YaraSuspicious
  * Description: Encapsulates a variety of Yara Scans.
  * THIS IS THE CLASS AutomateYara Returns
  */
final case class YaraSuspicious(packers: Vector[YaraParse],
                                antidebug: Vector[YaraParse],
                                exploitKits: Vector[YaraParse],
                                webshells: Vector[YaraParse],
                                cve: Vector[YaraParse],
                                malDocs: Vector[YaraParse],
                                suspStrings: Vector[YaraParseString]){
  override def toString(): String = {
    "\n\nPackers:\n" +
      packers.mkString("\n") +
      "\n\nAnti-Debug:\n" +
      antidebug.mkString("\n") +
      "\n\nExploit Kits:\n" +
      exploitKits.mkString("\n") +
      "\n\nWebshells:\n" +
      webshells.mkString("\n") +
      "\n\nCVEs:\n" +
      cve.mkString("\n") +
      "\n\nMalicious Documents:\n" +
      malDocs.mkString("\n") +
      "\n\nSuspicious Strings:\n" +
      suspStrings.mkString("\n")
  } // END toString()
} // END YaraSuspicious case class

/****************************************************************************************************/
/****************************************************************************************************/
/**************************************** AutomateYara Object ***************************************/
/****************************************************************************************************/
/****************************************************************************************************/

object AutomateYara extends VolParse with SearchRange {
  private[windows] def run( os: String,
           memFile: String,
                            kdbg: String,
           process: Vector[ProcessBbs],
           net: Vector[NetConnections],
           dllInfo: Vector[DllInfo] ): YaraBrain = {

    val allDllInfo: Vector[Vector[DllHexInfo]] = for(dll <- dllInfo) yield dll.memRange

    println("\n\nScanning memory with yara...\n\n")
    val netOutgoing: Vector[(String, String)] = net.filter( _.unknownDestIp ).map(x => (x.pid, x.srcIP))
    val netIncoming = net.filter(_.unknownSrcIp).map(x => (x.pid, x.destIP))
    val srcToPid = netIncoming ++: netIncoming
    // (pid, destination IP)

    val pids: Vector[String] = process.map(x => x.pid)
    val netPids = srcToPid.map(_._1)

    /** Filter dllInfo so it only contains processes w/ outgoing connections. */
    val locateDll: Vector[Vector[DllHexInfo]] = for{
      dllInfo <- allDllInfo
      if dllInfo.exists(x => netPids.contains(x.pid))
    } yield dllInfo

    val flatLocateDll: Vector[DllHexInfo] = locateDll.flatten

    println("Attempting to flatten locateDll...\n\n")
    flatLocateDll.foreach(println)

    // (pid -> Pertinent yara info )
    val ipCheck: Vector[(String, Vector[YaraParse])] = {
      runIp(memFile, os, kdbg, netOutgoing, pids)
    } // END ipCheck

    /**
      * NEED TO TEST!!!
      */

    /** Vector of Array that contains offsets. I THINK THIS WORKS! */
    val ipOffset: Vector[Vector[String]] = ipCheck.map(x => x._2.map(y => y.offset))

    println("Printing IP offsets\n\n")
    for{
      value <- ipOffset
      result <- value
    } println("Offset: " + result)

    val flatOffset: Vector[String] = ipOffset.flatten
    println("Testing out flatOffset...\n\n")
    flatOffset.foreach(println)

    /*******************************
      * MAJOR LOGIC PROBLEM HERE!!
      * While loop would be easier.
      * Make separate method.
      ******************************/

    val searchHex = searchRange(flatLocateDll, flatOffset)
      /** This is a miracle method... if it actually works... */
    // val searchHex: Vector[Vector[String]] = searchAll(locateDll, flatOffset)

    println("\n\nTIME FOR THE ULTIMATE TEST OF THE HEX WORK!!!!\n\n")
    for{ value <- searchHex
         result <- value } println(result(1) + " " + result(2) + result(3) )
    // searchHexRange.foreach(println)

    println("\n\nScanning for URLs with yara...\n\n")
    val urls: Vector[YaraParseString] = findUrls(memFile, os, kdbg)

    println("\n\nScanning for packers with yara...\n\n")
    val packers: Vector[YaraParse] = findPackers(memFile, os, kdbg)

    println("\n\nScanning for anti-debug signatures with yara...\n\n")
    val antidebug: Vector[YaraParse] = findAntiDebug(memFile, os, kdbg)

    println("\n\nScanning for exploit kits with yara...\n\n")
    val exploitKits: Vector[YaraParse] = findExploitKits(memFile, os, kdbg)

    println("\n\nScanning for malicious documents with yara...\n\n")
    val malDocs: Vector[YaraParse] = findMalDocs(memFile, os, kdbg)

    println("\n\nScanning for webshells with yara...\n\n")
    val webshells: Vector[YaraParse] = findWebshells(memFile, os, kdbg)

    println("\n\nScanning for known CVEs with yara...\n\n")
    val cveFound: Vector[YaraParse] = findCVE(memFile, os, kdbg)

    println("\n\nScanning for IPs in processes with yara...\n\n")
    val ipRule: Vector[YaraParseString] = findIpRule(memFile, os, kdbg)

    println("\n\nScanning for suspicious strings with yara...\n\n")
    val suspString: Vector[YaraParseString] = findSuspStrings(memFile, os, kdbg)

    /** Output too verbose to be useful. Would need to scan specific PID. */
    // val base64: Vector[YaraParseString]  = findBase64(memFile, os)

    println("\n\nScanning for malware with yara...\n\n")
    /** Malware Checks */
    val mal1: Vector[YaraParseString] = checkForMal1(memFile, os, kdbg)
    val mal2: Vector[YaraParseString] = checkForMal2(memFile, os, kdbg)
    val mal3: Vector[YaraParseString]  = checkForMal3(memFile, os, kdbg)
    val mal4: Vector[YaraParseString]  = checkForMal4(memFile, os, kdbg)

    /** Concat all malware scans together. */
    val concatMal: Vector[YaraParseString] = mal1 ++: mal2 ++: mal3 ++: mal4

    /** Print results for malware scan */
    println("\n\nPrinting findings from malware detection scan...\n\n")

    concatMal.foreach(println)

    /** There are so many scans that we had to encapsulate some of the scans in a different object. */
    val lowHitScans: YaraSuspicious = {
      YaraSuspicious(packers, antidebug, exploitKits, webshells, cveFound, malDocs, suspString)
    }

    println("\n\nScanning for cryptography in process memory...\n\nThis may take a while...\n\n")
    val crypto: Vector[YaraParse] = findCrypto(memFile, os, kdbg)

    /** When this program is run main full program, this will be returned */
    return YaraBrain(urls, ipRule, concatMal, lowHitScans, crypto, searchHex)
  } // END run()

  private[this] def runIp(memFile: String, os: String,  kdbg: String, info: Vector[(String, String)], pids: Vector[String]) = {

    val uniqInfo = info.distinct

    val ipResult: Vector[(String, Vector[YaraParse])] = {
      for(ip <- uniqInfo) yield findIps(memFile, os, kdbg, ip._1, ip._2, pids)
    }

    ipResult
  } // END runIp()

  /** Convert hexidecimal value to Long */
  private[this] def hex2Int(hex: String): Long = {
    val bigInt = new BigInteger(hex.drop(2), 16)
    return bigInt.longValue()
    // hex.toList.map("0123456789abcdef".indexOf(_)).reduceLeft(_ * 16 + _)
  }

  /** Search hex ranges for DLLs inside them. */
  private[this] def searchRange(dllHex: Vector[DllHexInfo], hexItem: Vector[String]): ArrayBuffer[ArrayBuffer[String]] = {

    println("Running searchRange()\n\n")
    var i = 0
    var j = 0
    var buff = ArrayBuffer[ArrayBuffer[String]]()

    var bool = false

    while (i < hexItem.length){
      j = 0
      while(j < dllHex.length){
        bool = searchHexRange(hexItem(i), dllHex(j).lowHex, dllHex(j).highHex)
        if(bool){
          /** SHOULD CLEAN UP hexItem!!! */
            println(s"Searching for ${hexItem(i)} between ${dllHex(j)} and ${dllHex(j)}\n")
          val hexLong = Try(hexItem(i).toLong).getOrElse(0L)
          val tup = ArrayBuffer(dllHex(j).dllName, dllHex(j).pid, "0x" + hexLong.toHexString )
          buff ++: tup
        }
        j = j + 1
      }
      i = i + 1
    } // END while

    for(value <- buff) println("PID: " + value(1) + "Dll Name: " + value(0) + "\nOffset: " + value(3))

    return buff
  } // END searchHexRange

  /**************************************
    * This rule might be too expensive
    *************************************/
  /** Find IPs in processes */
  private[this] def findIpRule(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {
    /*
    val ip = Try( s"python vol.py -f $memFile --profile=$os yarascan -y ip.yar".!!.trim )
      .getOrElse("Nothing found.")

   return parseYaraString(ip)
*/
    return Vector(YaraParseString("", "", ""))
  } // END findIpRule

  /** Find suspicious string. */
  private[this] def findSuspStrings(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y suspicious_strings.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y suspicious_strings.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    parseYaraString(str)
  } // END findSuspStrings()

  /** Run scan to look for malware */
  private[this] def checkForMal1(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {

    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y malware_rule1.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y malware_rule1.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    parseYaraString(str)
  } // END checkForMal1()

  /** Run scan to look for malware */
  private[this] def checkForMal2(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y malware_rule2.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y malware_rule2.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    parseYaraString(str)
  } // END checkForMal1()

  /** Run scan to look for malware */
  private[this] def checkForMal3(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {

    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y malware_rule3.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y malware_rule3.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    parseYaraString(str)
  } // END checkForMal1()

  /** Run scan to look for malware */
  private[this] def checkForMal4(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y malware_rule3.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y malware_rule3.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    parseYaraString(str)
  } // END checkForMal1()

  /*
    private[this] def findBase64(memFile: String, os: String): Vector[YaraParseString] = {
      val base64 = Try( s"python vol.py -f $memFile --profile=$os yarascan -y base64.yar".!!.trim )
        .getOrElse("Nothing found.")

      println(base64)

      parseYaraString(base64)

    } // END findBase64()
  */
  /*
    private[this] def findMalOperations(memFile: String, os: String): Vector[YaraParse] = {
      val opBlockbuster = Try( s"python vol.py -f $memFile --profile=$os yarascan -y operation_blockbuster_rule.yar".!!.trim )
        .getOrElse("Nothing found.")

      parseYaraResults(opBlockbuster, "Operation BlockBuster Malware")
    } // END findMalOperations()
    */

  /***************************************
    * PROBLEM WITH MISSING yara rules file!!
    **************************************/
  /** Find URLs in processes */
  private[this] def findUrls(memFile: String, os: String, kdbg: String): Vector[YaraParseString] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y url.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y url.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    return parseYaraString(str)
  } // END findUrls()

  /*************************************
    * This scan might be too expensive.
    ************************************/
  /** Find type of crypto used in processes */
  private[this] def findCrypto(memFile: String, os: String, kdbg: String): Vector[YaraParse] = {
/*
    val cryptoSigs = Try( s"python vol.py -f $memFile --profile=$os yarascan -y crypto_signatures.yar".!!.trim )
      .getOrElse("No crypto signatures found.")

    val parseSigs = parseYaraResults(cryptoSigs, "Crypto Signatures").sortBy(_.owner)

    return parseSigs
    */
    return Vector(YaraParse("", "", "", ""))
  } // END findCrypto()

  private[this] def findExploitKits(memFile: String, os: String, kdbg: String): Vector[YaraParse] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan -y exploitkits_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -y exploitkits_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }


    val parseExploits = parseYaraResults(str, "Exploit Kit Signatures").sortBy(_.owner)

    return parseExploits
  } // END findExploitKits()

  /** Will search for an IP address in process memory */
  private[this] def findIps(memFile: String, os: String, kdbg: String, pid: String, ip: String, pids: Vector[String]): (String, Vector[YaraParse]) = {
    var yaraByIp = ""

    val ipNoPort = ip.splitLast(':')(0)

    var str = ""
    if(kdbg.nonEmpty){
      if (pids.contains(pid)){
        println(s"Search for IP addresses for PID: $pid with Port Number: $ipNoPort...\n\n")

        yaraByIp = {
          Try( s"python vol.py --conf-file=user_config.txt yarascan -p $pid -W --yara-rules=$ipNoPort".!!.trim )
            .getOrElse(s"No results for $ipNoPort in $pid")
        }
      }
    }else{
      if (pids.contains(pid)){
        println(s"Search for IP addresses for PID: $pid with Port Number: $ipNoPort...\n\n")

        yaraByIp = {
          Try( s"python vol.py -f $memFile --profile=$os yarascan -p $pid -W --yara-rules=$ipNoPort".!!.trim )
            .getOrElse(s"No results for $ipNoPort in $pid")
        }
      }
    }

    val yaraParsed: Vector[YaraParse] = parseYaraResults(str, "IP")

    return (pid, yaraParsed)
    // Need to parse the results

  } // END findIps()

  private[this] def findMalDocs(memFile: String, os: String, kdbg: String): Vector[YaraParse] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan --yara-rules=malicious_documents_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan -yara-rules=malicious_documents_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    val malDocsParsed = parseYaraResults(str, "Malicious Documents").sortBy(_.owner)

    return malDocsParsed
  } // END findMalDocs()

  private[this] def findWebshells(memFile: String, os: String, kdbg: String): Vector[YaraParse] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan --yara-rules=webshell.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan --yara-rules=webshell.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    val shellsParsed = parseYaraResults(str, "Webshells").sortBy(_.owner)

    return shellsParsed
  } // END findWebshells()

  private[this] def findCVE(memFile: String, os: String, kdbg: String): Vector[YaraParse] ={
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan --yara-rules=cve_rules.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan --yara-rules=cve_rules.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    val cveParsed = parseYaraResults(str, "CVE").sortBy(_.owner)

    return cveParsed
  } // END findCVE()

  private[this] def findAntiDebug(memFile: String, os: String, kdbg: String):  Vector[YaraParse] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan --yara-rules=antidebug_antivm.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan --yara-rules=antidebug_antivm.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    val debugParsed = parseYaraResults(str, "Anti-Debug").sortBy(_.owner)

    return debugParsed
  } // END findAntiDebug()

  /** Searched for packers used to obfuscate code. */
  private[this] def findPackers(memFile: String, os: String, kdbg: String):  Vector[YaraParse] = {
    var str = ""
    if(kdbg.nonEmpty){
      str = Try( s"python vol.py --conf-file=user_config.txt yarascan --yara-rules=packers_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }else{
      str = Try( s"python vol.py -f $memFile --profile=$os yarascan --yara-rules=packers_rule.yar".!!.trim )
        .getOrElse("Nothing found.")
    }

    val packersParsed = parseYaraResults(str, "Packers").sortBy(_.owner)

    return packersParsed
  } // END findPackers()

  /** Extract the most useful section of the yara scan so we can pretty print. */
  private[this] def parseYaraResults(str: String, name: String): Vector[YaraParse] = {

    val splitResults: Vector[String] = str.split("""Rule:""").toVector
    val cleanerSplit = splitResults.filterNot(x => x.isEmpty)

    val extraSplit: Vector[Vector[String]] = {
      splitResults.map(x => Source.fromString(x).getLines.map(_.trim).filterNot(_.isEmpty).toVector)
    }

    val yar: Vector[YaraParse] = for{
      line <- extraSplit
      if line.length > 3
    } yield YaraParse(name, line(0), line(1).replaceAll("Process", ""), line(2).split(' ')(0))

    yar.foreach(println)

    return yar
  } // END parseYaraResults()

  /********************************************
    * NEED TO ADJUST FOR PARSING IP (NO CHARS)
    *******************************************/

  private[this] def parseYaraString(str: String): Vector[YaraParseString] = {
    val splitResults: Vector[String] = str.split("""Rule:""").toVector

    // Array of rows, with array of info.
    val extraSplit: Vector[Vector[String]] = {
      splitResults.map(x => Source.fromString(x).getLines.map(_.trim).filterNot(_.isEmpty).toVector)
    }

    /***********************************************************************************
      **********************************************************************************
      * splitProtect() should possibly split on more periods.
      **********************************************************************************
      **********************************************************************************/
    // contains the last column. We need to con
    val url: Vector[Vector[String]] = for {
      line <- extraSplit
      if line.length > 9
    } yield Vector(line(0), line(1), {line(2).split("\\s+").last + line(3).split("\\s+").last +
      line(4).split("\\s+").last + line(5).split("\\s+").last + line(6).split("\\s+").last +
      line(7).split("\\s+").last + line(8).split("\\s+").last + line(9).split("\\s+").last +
      line(10).split("\\s+").last + line(11).split("\\s+").last + line(12).split("\\s+").last +
      line(13).split("\\s+").last + line(14).split("\\s+").last + line(15).split("\\s+").last +
      line(16).split("\\s+").last }.splitProtect("""\.\.\.\.""")(0))

    /** Replace all occurrences of ".." or "..." with a single period. */
    val replaceExtraPeriods = replaceTwoOrThree(url)
    // Regex to remove "Process" from line.
    val regex = "Process\\s".r

    /** Code will be removed when program runs. */
    for{
      line <- replaceExtraPeriods
      result <- line
    } println(result)

    val yaraUrl = replaceExtraPeriods.map(x => YaraParseString( x(0), regex.replaceAllIn(x(1), ""), x(2)))

    /*
    val yar: Array[YaraParse] = for{
      line <- extraSplit
      if line.length > 3
    } yield YaraParseUrl( "url", line(0), line(1), line(2).split(' ')(17))
    val dropExtra = extraSplit.map(_.drop())
*/
    return yaraUrl
  } // END parseYaraUrls()

  /** Replace all sequences of periods w/ single periods. */
  def replaceTwoOrThree(url: Vector[Vector[String]]): Vector[Vector[String]] = {
   val regex3 = "\\.\\.\\.".r
   val regex2 = "\\.\\.".r

   val replace3: Vector[Vector[String]] = url.map(x => x.map(y => regex3.replaceAllIn(y, ".")))
   val replace2: Vector[Vector[String]] = replace3.map(x => x.map(y => regex2.replaceAllIn(y, ".")))

   return replace2
  } // END removeTwoOrThree

} // END AutomateYara object
/****************************************************************************************************/
/****************************************************************************************************/
/*********************************** DetectRegPersistence Object ************************************/
/****************************************************************************************************/
/****************************************************************************************************/

/**
  * I'm leaving the code to create a map to all repeated handles with a lot of repeat links,
  * but this will probably need to be removed eventually because the map contains information
  * that is not helpful. We are more concerned with the Run key than the other keys.
  */
/** (Key -> count),(Key -> Scan Results) */
case class RegPersistenceInfo(persistenceMap: mutable.Map[String, Int],
                              scanMap: mutable.Map[String, Option[String]],
                              handles: RegistryHandles){
  override def toString( ): String = {

    var persistenceMapInfo = s"The ${handles.runKey} occurs ${handles.runCount} times.\n\nIf there are a lot of links" +
      s"to the Run key from this process, it is likely that an attacker established persistence to pid: ${handles.pid}"
    var scans = ""
    for ((key, value) <- scanMap){
      val occurrences = scanMap(key).getOrElse(0)
      persistenceMapInfo = persistenceMapInfo + s"\n$key occurred $occurrences times."
      scans = s"\n" + scans + s"$key\n" + value.getOrElse("THERE WERE NO SCAN RESULTS FOR THIS VALUE")
    }
    if (scanMap.nonEmpty){
      s"%nThere were multiple indications that an attacker might have established registry Persistence: " +
        persistenceMapInfo + scans
    } else {
      "There is no indication that an attacker set up links to the registry to maintain persistence.\n" +
        persistenceMapInfo
    } // END if/else
  } // END toString()

} // END case class RegPersistenceInfo

case class RegistryHandles(pid: String,                   // pid
                           map: mutable.Map[String, Int], // map of process to count
                           runKey: Vector[String],        // Information in run key
                           runCount: Int)                 // Number of times run occurred.

object DetectRegPersistence extends VolParse {

  /***********************************************************************************
    * THIS SHOULD ACCEPT A VECTOR[PID] SO WE DON'T HAVE TO CREATE SO MANY OBJECTS!!!!
    **********************************************************************************
    **********************************************************************************/
  def run( mem: String, os: String, kdbg: String, pid: String, offset: String, hid: Boolean ): RegPersistenceInfo = {
    val persistHandles: RegistryHandles = regPersistence( mem, os, kdbg, pid, offset, hid )
    val testResult: ArrayBuffer[String] = regCountTest( persistHandles.map )
    val interrogation = interrogateReg(mem, os, kdbg, testResult, persistHandles)

    return interrogation
  } // END run()
  /**
    * regPersistence()
    * Looks for repeat links to the Run key which is indicative that an attacker
    * @param memFile
    * @param os
    * @param pid
    * @return RegistryHandles contains each duplicate value and the number of
    *         occurrences in a Map[String, Int], the FQDN to the RUN key for this system,
    *         and the count of the times run occurs.
    */
  def regPersistence( memFile: String, os: String, kdbg: String, pid: String, offset: String, hid: Boolean ): RegistryHandles = {
    var detectRegPersistence = ""
    if(kdbg.nonEmpty){
      if (hid) {
        detectRegPersistence = {
          Try(s"python vol.py --conf-file=user_config.txt --offset=$offset".!!.trim).getOrElse("")
        }
      }else{
        detectRegPersistence = {
          Try( s"python vol.py --conf-file=user_config.txt handles --object-type=Key --pid=$pid".!!.trim ).getOrElse("")
        }
      }
    }
    else {
      if (hid) {
        detectRegPersistence = {
          Try(s"python vol.py -f $memFile --profile=$os handles --object-type=Key --offset=$offset".!!.trim).getOrElse("")
        }
      } else {
        detectRegPersistence = {
          Try(s"python vol.py -f $memFile --profile=$os handles --object-type=Key --pid=$pid".!!.trim).getOrElse("")
        }
      }
    }

    /** We need to look through registry key names and find ones w/ numerous open handles to the same key */
    val regPersistVec: Vector[String] = {
      parseOutputDashVec( detectRegPersistence )
    }.getOrElse( Vector[String]() )
    val runKeys: Option[Vector[String]] = Some(regPersistVec.filter(_.endsWith("RUN")))
    val runCount = runKeys.getOrElse(Vector[String]()).length

    /** Contains a Vector of each value with a duplicate */
    val dupKeys = regPersistVec.diff( regPersistVec.distinct ).distinct

    /** Loop through and count the occurrences of each duplicate item */
    var mapToCount = mutable.Map[String, Int]()
    var i = 0
    var j = 0
    while ( i < dupKeys.length ) {
      var count: Int = 0
      j = 0
      while ( j < regPersistVec.length ) {
        if ( regPersistVec( j ) equals dupKeys( i ) ) {
          count += 1
          j += 1
        } // END if
      } // END inner while
      mapToCount += (dupKeys( i ) -> count)
      i += 1
    } // END while

    return RegistryHandles(pid, mapToCount, runKeys.getOrElse(Vector("", "")), runCount)
  } // END regPersistence()

  /** Returns an Array of each key that occurred 3 or more times  */
  def regCountTest( map: mutable.Map[String, Int] ): ArrayBuffer[String] = {
    val arr: ArrayBuffer[String] = ArrayBuffer[String]()
    for ( (key, value) <- map ) {
      if ( value > 2 ) arr += key.trim
    } // END for

    return arr
  } // END regExamCountTest

  def interrogateReg( memFile: String,
                      os: String,
                      kdbg: String,
                      arr: ArrayBuffer[String],
                      handles: RegistryHandles): RegPersistenceInfo = {

    val map = handles.map
    val scans: ArrayBuffer[Option[String]] = ArrayBuffer[Option[String]]()
    val regMap: mutable.Map[String, Int] = mutable.Map[String, Int]()
    val scanMap: mutable.Map[String, Option[String]] = mutable.Map[String, Option[String]]()

    for(key <- arr) {
      scanMap += {
        if(kdbg.nonEmpty){
          (key -> Some( s"python --conf-file=user_config.txt printkey -K $key".!!.trim ))
        }else{
          (key -> Some( s"python vol.py -f $memFile --profile=$os printkey -K $key".!!.trim ))
        }
      }
      regMap += (key -> map(key))
    }

    return RegPersistenceInfo(regMap, scanMap, handles )
  } // END interrogateReg()
} // END RegPersistence object

/**
/*************************** VadScan object **************************/
object VadScan extends VolParse {

  def run(os: String, memFile: String, pid: String): Unit = {
    /** (heapLoc_1 = allHeapLocs, heapLoc_2 = especially important heap locations (contains "extra" flag)) */
    val heapLoc(Vector[String], Vector[Option[String]]) = getHeapLoc(os, memFile, pid)
    val vadInfo: Option[String] = Some(s"python vol.py -f $memFile --profile=$os vadinfo -p $pid")

    /** Before we run vadinfo we need to filter out only the VADs that contain process heaps.
  *
  * It'd be nice to break down vadinfo output into separate Array locations to make filtering easy.
  * What indicator is there that a VAD start starts and stops.
  * */

    // We need to filter out items with VadS and that start with VAD node Flags, Protection, FileObject, Vad Type
    // The reason we keep VAD node is so we can figure out each time the collection is dealing with a different node.
    // Keep items that start with Control Flags and contain Image

    // If node starts with Flags: but does not contain CommitCharge or MemCommit, the memory range is reserved,
    // but the OS has not paired it with any physical pages.

    // NOTES:
    // CommitCharge Flag: Specifies the number of pages committed in the region described by the VAD node
    // Protection Flag: Don't assume too much based on the Protection flag because it can change.
    // PrivateMemory: A process' heaps, stacks, and ranges allocated with VirtualAlloc or VirtualAllocEx
    // are usually marked as private. (indication of possible code injection (204))
    // VirtualAllocEx is used to allocate memory in a remote process.
    // If the PrivateMemory bit is set for a memory region, it does not contain mapped files,
    // named shared memory, and copy-on-write DLLs.

    /** After we get a nice chunk of info about memory regions we should check out, use vaddump to dump to disk.
  * Need to pass the start address to vaddump
  */

  } // END run()

  /**
  * getHeapLoc()
  * Narrow down our search of a process by locating heaps.
  * @return Tuple: (Vector[Option[String]], Vector[Option[String]])
  *         (All heap memory locations, important heap locations because they contain "extra" flag)
  * */
  def getHeapLoc(os: String, memFile: String, pid: String): (Vector[Option[String]], Vector[Option[String]]) = {
    val heapInfo = Some(s"python vol.py -f $memFile --profile=$os heaps -p $pid")
    val parsedHeapInfo = parseOutputAsterisks(heapInfo.getOrElse("")).getOrElse(Vector[String]())
    val pattern = """0x\d+""".r
    val pattern_HEAP = """_HEAP+""".r
    /** Find the VADs heapLocs to help us narrow the amount of data we need to search through (224)
  * This might be more useful for general forensics versus intrusion detection/malware analysis */
    val heapLocs = parsedHeapInfo.map(x => pattern_HEAP.findAllIn(x).toString)
    val allHeapsMemLoc = heapLocs.map(x => pattern.findFirstIn(x))
    /** Contains heap locations with "extra" flag. More important than heapLocs in general. */
    val heapLocsExtra: Vector[Option[String]] = parsedHeapInfo.filter(_.contains("extra"))
      .map(x => pattern.findFirstIn(x))

    /** we can pass this info to volshell to see what's there with db(memLoc) (pg. 226) */
    return (allHeapsMemLoc, heapLocsExtra)
  } // END getHeapLoc()

} // END VadScan object
  */

/**
  * IDEAS:
  * Write loop to create regexes like this "\w+system32/\w+[kernel32.dll]
  * - the [kernel32.dll] part of regex can be created using list generated from prefetch parser.
  * - maybe write it to detect any paths with variations of system32 also
  *
  * Look for DLLs (I'm sure there are others):
  * ws2_32.dll - networking
  * crypt32.dll - cryptography
  * hnetcfg.dll - firewall maintenance
  * pstorec.dll - access to protected storage
  */

/****************************************************************************************************/
/****************************************************************************************************/
/*********************************** DetectUnlinkedDlls Object **************************************/
/****************************************************************************************************/
/****************************************************************************************************/
/*
 * NOTE!!!!!!
 * If an unlinked DLL is found, it'd be a good idea to do a svcscan and see if a service starts from it.
 */
final case class LdrInfo( pid: String,
                          baseLoc: Vector[String],   // base location of DLL.
                          probs: Vector[String],     // Finds lines that indicate there's an unlinked DLL.
                          dllName: Vector[String],
                          meterpreter: Boolean = false){  // Vector of problem DLL names
  override def toString: String = {

    val cleanProb = for{
      prob <- probs
      if prob.nonEmpty
    } yield prob

    if(cleanProb.isEmpty)""
    else cleanProb.map(_.trim).mkString("\n")
  } // END toString()
} // END LdrInfo case class

final case class DllInfo(pid: String, memRange: Vector[DllHexInfo], command: String){
  override def toString: String = "Pid: " + pid + "\nCommand Found: " + command + "\n"
} // END DllInfo case class

/****************************************************
  *
  * This section still needs a lot of testing.
  *
  ***************************************************/
object DllScan extends VolParse {

  def run(os: String, memFile: String, kdbg: String, pidVec: Vector[ProcessBbs]): (Vector[DllInfo], Vector[LdrInfo]) ={
    /** ldrMemLoc contains memory locations we'll pass to dlldump & ldrFullScan contains filtered scan */
    val ldrInfo : Vector[LdrInfo] =
      for{procBbs<- pidVec
      } yield ldrScan(memFile, os, kdbg, procBbs.pid, procBbs.offset, procBbs.hidden)

    val dllInfo: Vector[DllInfo] = for{
      procBbs<- pidVec
    } yield dllListScan(memFile, os, kdbg, procBbs.pid, procBbs.offset, procBbs.hidden)

    return (dllInfo, ldrInfo)
  } // END run()

  /**
    * ldrScan()
    * Runs ldrmodules and finds helpful information.
    * @param memFile
    * @param os
    * @param pid
    */
  private[this] def ldrScan(memFile: String, os: String, kdbg: String, pid: String, offset: String, hid: Boolean): LdrInfo = {
    /** We want to find each process that has a False value in it.
      * We also want to look for executables w/ no Mapped Path */

    /**
    // regex to find exec w/ no mapped path. NOT USED IN CODE!!
    */
    val noMappedPath = ".*\\.\\.".r

    var ldr = ""
    if(kdbg.nonEmpty){
      if(hid)
        ldr = Try( s"python vol.py --conf-file=user_config.txt --offset=$offset -v".!!.trim ).getOrElse("")
      else
        ldr = Try( s"python vol.py --conf-file=user_config.txt ldrmodules -p $pid -v".!!.trim ).getOrElse("")
    }
    else {
      if (hid)
        ldr = Try(s"python vol.py -f $memFile --profile=$os ldrmodules --offset=$offset -v".!!.trim).getOrElse("")
      else
        ldr = Try(s"python vol.py -f $memFile --profile=$os ldrmodules -p $pid -v".!!.trim).getOrElse("")
    } // END if/else kdbg.nonEmpty

    val ldrParsed: Vector[String] = parseOutputNoTrim(ldr).getOrElse(Vector[String]())

    /*****************************
      * LOOK FOR meterpreter DLL.
      * metsrv.dll
      ****************************/

    val ldrLower = ldrParsed.map(_.toLowerCase).filter(x => x.endsWith("dll"))

    /** Look for meterpreter dll and create Vector[Boolean]. Remove false*/
    val meterpreter = ldrParsed.map(x => x.contains("metsrv.dll"))
      .filterNot(_ == false)

    var meterBool = false

    /** If the meterpreter dll is in there, set meterBool to true */
    if (meterpreter.nonEmpty) meterBool = true
    /**************************************************************************************************************
      * Verbose output includes paths. Should probably check for path discrepancies before filter (Warning p. 238)
      *************************************************************************************************************/
    val problems: Vector[String] = ldrLower.filter(_.contains("false"))
    val problemsFound = problems.filter(x => x.contains(".dll"))
    val trimmedProbs: Vector[String] = problemsFound.map(_.trim)

    val cleanedProbs: Vector[String] = for{
      prob <- trimmedProbs
      if prob.nonEmpty
    } yield prob

    if(cleanedProbs.nonEmpty){
      println("\nPrinting hidden DLL that was found...")
      cleanedProbs.foreach(println)
      println("")
    }

    val pattern = "0x\\w+".r
    val baseLocations: Vector[String] = cleanedProbs.map(x => pattern.findFirstIn(x).getOrElse(""))

    val dllPattern = "\\w+\\.dll".r   // PREVIOUS REGEX: "\\w+\\.dll$".r
    // val nameLine = cleanedProbs.filter(_.contains("mem"))
    val dllName = cleanedProbs.map(x => dllPattern.findFirstIn(x).getOrElse(""))

    if(cleanedProbs.nonEmpty){
      println("\nPrinting hidden DLL Name: ")
      for(name <- dllName) println("Hidden DLL: " + name)
      println("")
    }

    LdrInfo(pid, baseLocations, cleanedProbs, dllName, meterBool)
  } // ldrScan()

  /** Returns PID, Vector with Memory Location range of DLL, and Command Line Information) */
  private[this] def dllListScan(memFile: String, os: String, kdbg: String, pid: String, offset: String, hid: Boolean): DllInfo = {

    var dllList = ""
    if(kdbg.nonEmpty){
      if (hid)
        dllList = Try( s"python vol.py --conf-file=user_config.txt dlllist --offset=$offset".!!.trim ).getOrElse("")
      else
        dllList = Try( s"python vol.py --conf-file=user_config.txt dlllist -p $pid".!!.trim ).getOrElse("")
    }else{
      if (hid)
        dllList = Try( s"python vol.py -f $memFile --profile=$os dlllist --offset=$offset".!!.trim ).getOrElse("")
      else
        dllList = Try( s"python vol.py -f $memFile --profile=$os dlllist -p $pid".!!.trim ).getOrElse("")
    } // END if/else kdbg.nonEmpty

    val parseAsterisks: Vector[String] = parseOutputAsterisks(dllList).getOrElse(Vector[String]())

    val commandLine = parseAsterisks.filter(_.contains("Command"))
    val filterDLL: Vector[String] = parseOutputDashVec(dllList).getOrElse(Vector[String]())

    val grabDllInfo: Vector[DllHexInfo] = locateDll(memFile, os, kdbg, pid, offset, hid)

    /** Filter out DLLs loaded because specified by IAT (not explicitly loaded) */
    val dllWithRemoveIAT = filterDLL.filterNot(_.contains("0xffff"))

    val dllWithProcRemoved: Vector[String] = dllWithRemoveIAT.filter(x => x.toLowerCase.contains(".dll"))

    /** RETURN Statement
      * We want to know pid, memory range, and commandline stuff. */
    if(commandLine.nonEmpty) DllInfo(pid, grabDllInfo, commandLine(0))
    else DllInfo(pid, grabDllInfo, "No Command Line Info")
  } // END dllListScan()

  /** Find DLL memory location ranges.  */
  private[this] def locateDll(memFile: String, os: String, kdbg: String,
                              pid: String, offset: String, hid: Boolean): Vector[DllHexInfo] = {
    var dllList = ""
    if(kdbg.nonEmpty){
      if (hid)
        dllList = Try( s"python vol.py --conf-file=user_config.txt --offset=$offset dlllist".!!.trim ).getOrElse("")
      else
        dllList = Try( s"python vol.py --conf-file=user_config.txt -p $pid dlllist".!!.trim ).getOrElse("")
    }
    else{
      if (hid)
        dllList = Try( s"python vol.py -f $memFile --profile=$os --offset=$offset dlllist".!!.trim ).getOrElse("")
      else
        dllList = Try( s"python vol.py -f $memFile --profile=$os -p $pid dlllist".!!.trim ).getOrElse("")
    }


    val parsed: Option[Vector[String]] = parseOutputDashVec(dllList)

    /** Filter out DLLs loaded because specified by IAT (not explicitly loaded) */
    val dllWithRemoveIAT = parsed.filterNot(_.contains("0xffff"))

    val parse2d: Option[Vector[Vector[String]]] = vecParse(dllWithRemoveIAT.getOrElse(Vector[String]()))
    val parsedRemoveOpt = parse2d.getOrElse(Vector[Vector[String]]())

    val pertinentInfo: Vector[Vector[String]] = {
      parsedRemoveOpt.map(x => Vector(Try(x(0)).getOrElse(""), Try(x(1)).getOrElse(""), Try(x(3)).getOrElse("")))
    }

    /** Here is where the error occurs */
    val hexRange: Vector[DllHexInfo] = for {
      line <- pertinentInfo
    } yield new DllHexInfo(pid, Try(line(2)).getOrElse("0"),
                Try(hex2Int(line(0))).getOrElse(0),
                Try(hex2Int(line(0))).getOrElse(0L) + Try(hex2Int(line(1))).getOrElse(0L) )

    return hexRange
  } // END locateDll()

  /** convert hex memory location to an integer. */
  private[this] def hex2Int(hex: String): Long = {
    val bigInt = new BigInteger(hex.drop(2), 16)

    return bigInt.longValue()
    // hex.toList.map("0123456789abcdef".indexOf(_)).reduceLeft(_ * 16 + _)
  } // END hex2Int

} // END DetectUnlinkedDLLs object
