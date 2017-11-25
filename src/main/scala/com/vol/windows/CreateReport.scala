package com.bbs.vol.windows

import java.text.SimpleDateFormat
import java.util.Calendar

import com.bbs.vol.processtree._
import com.bbs.vol.utils.FileFun

import scala.collection.immutable.TreeMap
import scala.util.Try

object CreateReport extends FileFun {

  private[windows] def run(memFile: String, os: String, process: ProcessBrain, disc: Discovery, riskRating: Int) = {

    var forRegex = ""

    /** Using StringBuilder for fast concatenation of Strings. */
    val report = new StringBuilder()

    /** Determine the date of the report and format it. */
    val intDate = Calendar.getInstance().getTime
    val dateFormat = new SimpleDateFormat("EEE, d MMM yyyy")
    val date = dateFormat.format(intDate)

    /**
      *
      */

    /** Grab info we need for report. */
    val proc: Vector[ProcessBbs] = disc.proc._1

    /** callbacks, hiddenModules, timers, deviceTree, orphanThread, found */
    val rootkit: RootkitResults = disc.rootkit

    /** (pid -> Remote Mapped Drive) */
    val remoteMapped: Vector[(String, String)] = disc.remoteMapped

    /** Vector[String], Vector[String] */
    // val registry = disc.registry

    /** svcStopped, suspCmds */
    val sysSt: SysState = disc.sysState
    val svc = sysSt.svcStopped

    val net: Vector[NetConnections] = disc.net._1

    /**
      * Get info from ProcessBrain
      */
    val yaraObj: YaraBrain = process.yara
    val regPersist: Vector[RegPersistenceInfo] = process.regPersistence // done
    val ldr: Vector[LdrInfo] = process.ldrInfo // done

    val promiscModeMap: Map[String, Boolean] = process.promiscMode

    /** Write Report */
    val intro = s"Big Brain Security Volatile IDS Report FOR $memFile $date\n\nSUMMARY:\n\nRISK RATING: $riskRating\n\n"

    /** Yara malware findings */
    val malware: String = malwareFound(yaraObj)

    if(malware.nonEmpty)
      report.append(intro +  "Malware Found:\n\n")

    report.append(malware)
    report.append("SIGNIFICANT FINDINGS:\n\n")

    /**Disabled Services */
    if(svc.nonEmpty)
      report.append("THE FOLLOWING SUSPICIOUS SERVICES WERE DISABLED:\n\n" + svc.mkString("\n\n"))

    /**Remote Mapped Drives */
    val mappedDriveVec = mappedDrives(remoteMapped)
    if(mappedDriveVec.nonEmpty){
      report.append("\nTHE FOLLOWING REMOTE MAPPED DRIVES WERE FOUND:\n" + mappedDriveVec.mkString("\n"))
    }

    /** Unlinked DLLs*/
    val ldrInfoCheck = ldrCheck(ldr)

    report.append(ldrInfoCheck)

    /**Rootkits Found */
    val rootkitInfo = rootkitCheck(rootkit)

    report.append(rootkitInfo)

    /** Promiscuous Mode*/
    if(promiscModeMap.nonEmpty) {

      report.append("\nTHE SYSTEM WAS PUT INTO PROMISCUOUS MODE BY THE FOLlOWING PID(S): " + promiscModeMap.keys.mkString(", "))
    }

    /** Hidden Processes*/
    val (hiddenStr, forRegexFile): (String, String) = hiddenProcs(proc)
    if(hiddenStr.nonEmpty){
      forRegex = forRegex + forRegexFile
      report.append("\nTHE FOLLOWING HIDDEN PROCESSES WERE FOUND:\n\nNOTE: " +
        "If the processes, is not used by anti-virus software, you probably have malware.\n\n"
        + hiddenStr)
    }

    /****************************************
      * STOPPED ADDING TO REGEX FILE HERE!!!
      ***************************************/

    /** Whether or not VNC is on the system. */
    val vnc = vncCheck(net)
    if(vnc.nonEmpty) report.append(vnc)

    /** Meterpreter DLL */
    val meterpreter = checkMeterpreter(ldr)
    if(meterpreter.nonEmpty)
      report.append(meterpreter)

    /** Memory Leaks*/
    val leaks = memoryLeaks(regPersist)
    if(leaks.nonEmpty)
      report.append(leaks)

    /** Run findHiddenExecs() and say if any execs were found. */
    val hiddenExec = findHiddenExecs(proc)
    if(hiddenExec.nonEmpty)
      report.append(hiddenExec)

    /** Suspicious Console Commands */
    if(sysSt.suspCmds.nonEmpty){
      report.append("\n\nTHE FOLLOWING POTENTIALLY SUSPICIOUS COMMANDS WERE FOUND IN THE COMMANDLINE INFO: \n\n")
      report.append(sysSt.suspCmds.mkString("\n"))
    }

    /** Commandline History */
    if(sysSt.consoles.nonEmpty){
      report.append("FULL COMMANDLINE HISTORY FOUND:\n\n")
      report.append(sysSt.consoles)
    }

    /** PROCESS INFO */

    val procTree = disc.proc._2
    report.append("\nPROCESS TREE RESULTS:\n\n" + procTree )

    val processInfo = writeProcessInfo(process, disc, yaraObj)

    report.append(processInfo)

    /** Write Report to File */
    writeToFile("BBS_Report_" + memFile + ".txt", report.toString)

  } // END run()

  /*****************************************************************
    * **************************************************************
    * **************Results Summary Section ************************
    * **************************************************************
    ****************************************************************/

  private[this] def writeProcessInfo(procBrain: ProcessBrain, disc: Discovery, yara: YaraBrain): String = {

    /** Vector[ProcessBbs] */
    val vec = disc.proc._1
    val ldr: Vector[LdrInfo] = procBrain.ldrInfo
    val net = disc.net._1

    val disclaimer = "NOTE: PROCESS NAMES CAN BE CHANGED!! Process descriptions are provided to give the investigator" +
      " context into what they are examining. Malicious code can be injected into a process. Do not assume that " +
      "the description of a process is authoritative.\n\n"

    val processStr = for(value <- vec) yield writeEachProcess(value, yara, ldr, net, procBrain, disc)

    val strResult = "\n\nProcess Information Summary:\n\n" + disclaimer + processStr.mkString("\n\n")

    return strResult
  } // END writeProcessInfo()

  private[this] def writeEachProcess(proc: ProcessBbs, yara: YaraBrain, ldr: Vector[LdrInfo],
                                     net: Vector[NetConnections], procBrain: ProcessBrain, disc: Discovery): String = {

    val procInfo: Vector[ProcessBbs] = disc.proc._1
    var description = ""
    val report = new StringBuilder()

    description = commonProcesses(proc.name.toUpperCase)

    if(description.isEmpty)
      description = ProcessDescription.get(proc.name.toUpperCase)

    val ppidVec = procInfo.filter(x => x.pid.contains(proc.ppid))

    val ppidName = if(ppidVec.nonEmpty) ppidVec.head.name else ""

    report.append("Name: " + proc.name + "  PID: " + proc.pid )

    if(ppidName.nonEmpty)
      report.append("\nPARENT NAME: " + ppidName)

    if(description.nonEmpty)
      report.append("\nDESCRIPTION: " + description)

    if(proc.hidden)
      report.append("\nHIDDEN: True")
    /** Check if metepreter dll was found in process or in parent. */
    val ldrPid = ldr.filter(x => x.pid.contains(proc.pid))
    val ldrPpid = ldr.filter(x => x.pid.contains(proc.ppid))
    var forReport = ""
    if(ldrPid.nonEmpty){
      val ldr = ldrPid.head
      /**
        * This should include a description
        */
      forReport = ldr.dllName.mkString("\n")
      if(ldr.meterpreter)
        report.append("\n\nMETERPRETER DLL FOUND: True!!!!!!")
    }
    if(ldrPpid.nonEmpty){
      val ldr = ldrPpid.head
      if(ldr.meterpreter)
        report.append(s"\n\nMETERPRETER DLL FOUND IN PARENT PROCESS $ppidName: True!!!!!!")
    }
    /** Add Dll command found */
    val dll: Vector[DllInfo] = procBrain.dllInfo
    val dllPerPid = dll.filter(x => x.pid.contains(proc.pid))
    val dllCommand = if(dllPerPid.nonEmpty) {
      dllPerPid.head.command
    }else{
      ""
    }

    if(dllCommand.nonEmpty)
      report.append("\n" + dllCommand)
    /** Check yara for malicious signatures found  */
    val checkYaraPid: (String, String) = checkYaraPerProcess(proc.pid, yara)
    val checkYaraPpid: (String, String) = checkYaraPerProcess(proc.ppid, yara)

    if(checkYaraPid._1.nonEmpty){
      forReport = forReport + checkYaraPid._2
      report.append("\n\nMALICIOUS SIGNATURES FOUND IN PROCESS:" + checkYaraPid)
    }
    if(checkYaraPpid._1.nonEmpty){
      forReport = forReport + checkYaraPpid._2
      report.append("\n\nMALICIOUS SIGNATURES FOUND IN PARENT PROCESS:" + checkYaraPpid)
    }

    // val remoteMapped = disc.remoteMapped

    /** Check if registry persistence occurred for process or parent.  */
    val regPersist: Vector[RegPersistenceInfo] = procBrain.regPersistence
    val persistence = regPersist.filter(x => x.handles.pid.contains(proc.pid))
    val ppidPersistence = regPersist.filter(x => x.handles.pid.contains(proc.ppid))

    /** There should only be one */
    if(persistence.nonEmpty) {
      val persistMap = persistence.head.scanMap
      val pidResult = persistMap.getOrElse(proc.pid, Some("0"))
      val ppidResult = persistMap.getOrElse(proc.ppid, Some("0"))
      if (pidResult.getOrElse("0") != "0") {
          report.append("\n\nREGISTRY PERSISTENCE INFO FOR CURRENT PROCESS: " + ppidPersistence.head)
        } // END if registry persistence exists
      if (ppidResult.getOrElse("0") != "0") {
          report.append(s"\n\nREGISTRY PERSISTENCE INFO FOR PARENT PROCESS $ppidName PID ${proc.ppid}: " + ppidPersistence.head)
      } // END if persistMap exists
    } // END persistenceMap.nonEmpty

    /** Add information about privileges */
    val privs = procBrain.privs
    val priv: Vector[Privileges] = privs.filter(x => x.pid.contains(proc.pid))

    if(priv.nonEmpty) {
      val privResult = priv.head

      if(privResult.debugPriv){
        report.append("\n\nDEBUG PRIVILEGE WAS EXPLICITLY ENABLED. ATTACKERS COMMONLY DO THIS.\n\n")
        report.append("\n\nSUSPICIOUS PRIVILEGES:\n" + privResult.suspiciousPrivs.mkString("\n"))
      }

      if(privResult.enabledPrivs.nonEmpty) {
        report.append("\n\nTHE FOLLOWING PRIVILEGES WERE EXPLICITLY ENABLED:\n" +
          privResult.enabledPrivs.mkString("\n"))
      }
    } // END priv nonEmpty

    /** Networking capability */
    // val netActivityMap = procBrain.netActivity

    // if(netActivityMap(proc.pid))report.append("\nNetworking Activity: True")
    //else report.append("\nNetworking Activity: Unknown")

    /** Add information about outside ip addresses */
    val connections = netActivity(disc.net._1, proc.pid)
    if(connections.nonEmpty)
      report.append(connections)

    /**
      * MAP!!
      */
    /** Malfind Results */
    val malfind = procBrain.malfind.getOrElse(proc.pid, "")
    val ppidMalfind = procBrain.malfind.getOrElse(proc.ppid, "")

    if(malfind.nonEmpty)
      report.append("\nMALFIND FOUND THE FOLLOWING RESULTS FOR " + proc.name + s"\n\n$malfind")
    if(ppidMalfind.nonEmpty)
      report.append(s"\nMALFIND FOUND THE FOLLOWING RESULTS FOR THE PARENT OF ${proc.name}: $ppidName PID ${proc.ppid}\n\n$ppidMalfind")

    val dlls: String = getDlls(dllPerPid.headOption)
    if(dlls.nonEmpty)
      report.append(s"\n\n${proc.name} DLL INFO:" + dlls)

    /**
      * NEED TO ADD METHOD FOR TRYING TO PRINT HIDDEN DLL INFO
      */

    val urls = checkYaraLessImportant(yara, proc.pid)


    if(urls.nonEmpty)
      report.append(urls)

    report.append("\n\n*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*\n")

    return report.toString
  } // writeEachProcess()

  private[this] def getDlls(dll: Option[DllInfo]): String = {

    val dllResult = dll.getOrElse(DllInfo("", Vector(DllHexInfo("", "", 0L, 0L)), ""))

    val dllNames: Vector[String] = if(dllResult.memRange.nonEmpty){
        dllResult.memRange.map(x => x.dllName)
    } else{
      Vector("NO INFO")
    }
    val allDllNames = dllNames.filterNot(x => x.isEmpty)

    val description: String = if(allDllNames.nonEmpty){
      val result = for(value <- allDllNames) yield (value, ProcessDescription.get(value.toUpperCase))
      val resultStr = for(value <- result) yield s"\n\nDLL: ${value._1}\nDESCRIPTION: ${value._2}"
      resultStr.mkString("\n")
    }else{
      ""
    } // END descriptionTup

    return description
  } // END getDlls()

  private[this] def netActivity(vec: Vector[NetConnections], pid: String): String = {
    var str = ""
    val pids: Vector[NetConnections] = vec.filter(x => x.pid.contains(pid))
    val srcIps: Vector[String] = pids.map(x => x.srcIP)
    val destIps: Vector[String] = pids.map(x => x.destIP)
    /** Removing local ip addresses */
    val srcFiltered = {
      srcIps.filterNot(_.startsWith("192\\."))
        .filterNot(_.startsWith("172\\."))
        .filterNot(_.startsWith("10\\."))
        .filterNot(_.contains("0\\.0\\.0\\.0"))
    }
    val destFiltered = {
      destIps.filterNot(_.startsWith("192\\."))
        .filterNot(_.startsWith("172\\."))
        .filterNot(_.startsWith("10\\."))
        .filterNot(_.contains("0\\.0\\.0\\.0"))
    }
    if(srcFiltered.nonEmpty){
      str = "\n\nThe following external source IP addresses were found:\n\n" + srcFiltered.mkString("\n")
    }
    if(destFiltered.nonEmpty){
      str = str + "\n\nThe following external destination IP addresses were found:\n\n" + destFiltered.mkString("\n")
    }

    return str
  } // END netActivity()


  /** Grab Yara info from processes */
  private[this] def checkYaraPerProcess(pid: String, yara: YaraBrain): (String, String) = {
    val report = new StringBuilder()
    var forRegex = false

    if(pid == "0")("", "")
    else {
      val suspItems = yara.suspItems
      val susStr = suspItems.suspStrings
      val malDoc = suspItems.malDocs
      val shells = suspItems.webshells
      val antidebug = suspItems.antidebug
      val cve = suspItems.cve
      val pack = suspItems.packers
      val exploitkits = suspItems.exploitKits
      val malware = yara.malware

      /** Find the entries included in the processes */
      val pidMal = malware.filter(x => x.proc.contains(pid)).distinct
      // val pidSuspStr = susStr.filter(x => x.proc.contains(pid)).distinct
      val pidMalDoc = malDoc.filter(x => x.owner.contains(pid)).distinct
      val pidShells = shells.filter(x => x.owner.contains(pid)).distinct
      val pidAnti = antidebug.filter(x => x.owner.contains(pid)).distinct
      val pidCVE = cve.filter(x => x.owner.contains(pid)).distinct
      val pidPack = pack.filter(x => x.owner.contains(pid)).distinct
      val pidExploit = exploitkits.filter(x => x.owner.contains(pid)).distinct

      /** Append to StringBuilder if found */
      if (pidMal.nonEmpty){
        forRegex = true
        report.append("\n\nMALWARE SIGNATURES FOUND:\n\n" + pidMal.mkString("\n"))
      }
      if (pidAnti.nonEmpty){
        forRegex = true
        report.append("\n\nANTIDEBUG SIGNATURES FOUND:\n\n" + pidAnti.mkString("\n"))
      }
      if (pidCVE.nonEmpty){
        forRegex = true
        report.append("\n\nCVES(MALWARE) FOUND:\n\n" + pidCVE.mkString("\n"))
      }
      if (pidExploit.nonEmpty){
        forRegex = true
        report.append("\n\nEXPLOIT KITS FOUND:\n\n" + pidExploit.mkString("\n"))
      }
      if (pidShells.nonEmpty){
        forRegex = true
        report.append("\n\nWEBSHELLS FOUND:\n\n" + pidShells.mkString("\n"))
      }
      if (pidMalDoc.nonEmpty){
        forRegex = true
        report.append("\n\nMALICIOUS DOCUMENTS FOUND:\n\n" + pidMalDoc.mkString("\n"))
      }
      if (pidPack.nonEmpty){
        forRegex = true
        report.append("\n\nPACKERS FOUND:\n\n" + pidPack.mkString("\n"))
      }
      val forRegexPrint = if(forRegex) pid else ""
      // if(pidSuspStr.nonEmpty)""
      (report.toString(), forRegexPrint)
    }

  } // END checkYaraPerProcess()

  private[this] def checkYaraLessImportant(yara: YaraBrain, pid: String): String = {
    var str = ""
    val urls: Vector[YaraParseString] = yara.url
    val pidUrls = urls.filter(x => x.proc.contains(pid)).distinct
    if(pidUrls.nonEmpty)
      str = "\n\nURLs FOUND BY YARA:\n" + pidUrls.mkString("\n")

    return str
  } // END

  /** Check for executables disguised as other processes. */
  private[this] def findHiddenExecs(vec: Vector[ProcessBbs]): String = {

    var str = ""
    val hiddenExecPattern = {
      Vector("\\.xlsx.exe", "\\.csv.exe", "\\.doc.exe", "\\.xls.exe", "\\.xltx.exe", "\\.xlt.exe",
        "\\.pdf.exe", "\\.xlsb.exe", "\\.xlsm.exe", "\\.xlst.exe", "\\.xml.exe", "\\.txt.exe",
        "\\.ods.exe", "\\.docx.exe", "\\.dot.exe", "\\.rtf.exe", "\\.docm.exe", "\\.dotm.exe",
        "\\.htm.exe", "\\.mht.exe", "\\.jpg.exe", "\\.ppt.exe", "\\.pptx.exe", "\\.pot.exe",
        "\\.odp.exe", "\\.ppsx.exe", "\\.pps.exe", "\\.pptm.exe", "\\.potm.exe", "\\.ppsm.exe",
        "\\.py.exe", "\\.pl.exe", "\\.eml.exe", "\\.json.exe", "\\.mp3.exe", "\\.wav.exe", "\\.aiff.exe",
        "\\.au.exe", "\\.pcm.exe", "\\.ape.exe", "\\.wv.exe", "\\.m4a.exe", "\\.8svf.exe", "\\.webm.exe",
        "\\.wv.exe", "\\.wma.exe", "\\.vox.exe", "\\.tta.exe", "\\.sln.exe", "\\.raw.exe", "\\.rm.exe",
        "\\.ra.exe", "\\.opus.exe", "\\.ogg.exe", "\\.oga.exe", "\\.mogg.exe", "\\.msv.exe", "\\.mpc.exe",
        "\\.mmf.exe", "\\.m4b.exe", "\\.ivs.exe", "\\.ilkax.exe", "\\.gsm.exe", "\\.flac.exe",
        "\\.dvf.exe", "\\.dss.exe", "\\.dct.exe", "\\.awb.exe", "\\.amr.exe", "\\.act.exe", "\\.aax.exe",
        "\\.aa.exe", "\\.3gp.exe", "\\.webm.exe", "\\.mkv.exe", "\\.flv.exe", "\\.vob.exe", "\\.ogv.exe",
        "\\.ogg.exe", "\\.gif.exe", "\\.gifv.exe", "\\.mng.exe", "\\.avi.exe", "\\.mov.exe", "\\.qt.exe",
        "\\.wmv.exe", "\\.yuv.exe", "\\.rm.exe", "\\.rmvb.exe", "\\.asf.exe", "\\.amv.exe", "\\.mp4.exe",
        "\\.m4p.exe", "\\.m4v.exe", "\\.amv.exe", "\\.asf.exe")
    } // END hiddenExecPattern

    /** Combine all the strings in the Vector to make a single regex */
    val makeRegex = ".+(" + hiddenExecPattern.mkString("|") + ")"
    val regex = makeRegex.r

    /** Vector of process names. */
    val procVec: Vector[String] = vec.map(x => x.name).distinct
    val searchForHiddenProcs = procVec.map(x => regex.findFirstIn(x))
    val hiddenProcs = searchForHiddenProcs.flatten

    if(hiddenProcs.nonEmpty) {
      hiddenProcs.foreach(println)
      str = str + "\n\nTHE FOLLOWING HIDDEN PROCESSES WERE FOUND:\n\n" + hiddenProcs.mkString("\n")
    } // END if nonEmpty

    return str
  } // END hiddenExecPattern

  /** Check for meterpreter DLL */
  private[this] def checkMeterpreter(vec: Vector[LdrInfo]) = {

    var str = ""

    val meter = vec.map(x => (x.pid, x.meterpreter))
    val meterFound = meter.filter(_._2 == true)
    if(meterFound.nonEmpty) {
      str = "\nA DLL used by meterpreter was found on the system indicating that the system was breached."
      val dllFound = for(value <- meterFound) yield s"\nA meterpreter DLL was found in PID: ${value._1}"
      str = str + dllFound.mkString("\n")
    }

    str
  } // END checkMeterpreter()

  private[this] def memoryLeaks(vec: Vector[RegPersistenceInfo]) = {

    var reportStr = ""
    val regHandles: Vector[RegistryHandles] = vec.map(x => x.handles)

    val count: Vector[(String, Int)] = regHandles.map(x => (x.pid, x.runCount))
    val filterCount = count.filter(_._2 > 3)

    var tempVec = Vector[String]()
    if (filterCount.nonEmpty){
      reportStr = "\nDuplicate run keys are an indication that an attacker used the registry to establish persistence.\n"
      tempVec = for(values <- filterCount) yield s"${values._2} links to the run key were found in PID: ${values._1}"
      reportStr = reportStr + tempVec.mkString("\n")

      if(filterCount.exists(x => x._2 > 8)) {
        reportStr = reportStr + {
          s"\n\nWe have determined that an attacker used the run key to establish registry persistence.\n"
        }
      }  // END if filterCount exists
    } // END if filterCount.nonEmpty()

    reportStr
  } // END memoryLeaks()

  private[this] def vncCheck(vec: Vector[NetConnections]): String = {

    var str = ""

    val vncCheck = for{
      value <- vec
      if value.vnc == true
    } yield "Source IP: " + value.srcIP +"Destination IP:" + value.destIP

    if(vncCheck.nonEmpty){
      str = "\nVNC was found on the system. This is remote desktop software commonly used for malicious and non-malicious reasons.\n" +
      vncCheck.mkString("\n")
    }

    return str
  } // END vncCheck()

  /** Return both hidden processes and */
  private[this] def hiddenProcs(procs: Vector[ProcessBbs]): (String, String) = {

    val hidden: Vector[(String, String)] = for{
      value <- procs
      if value.hidden == true
    } yield ("PID: " + value.pid + " Name: " + value.name, value.name)

    val names = hidden.map(x => x._2).filterNot(x => x.contains("system")).filterNot(x => x.contains("smss"))
    val forReport = hidden.map(x => x._1)
    val str = forReport.mkString("\n")

    return (str, names.mkString("\n"))
  } // END hiddenProcs()

  private[this] def rootkitCheck(root: RootkitResults): String = {

    val str = new StringBuilder()
    val callbacks = root.callbacks        // done
    val hiddenMods = root.hiddenModules   // done
    val orphan: String = root.orpanThread // done
    val timers: Vector[String] = root.timers              // done
    val ssdt = root.ssdtFound // done

    if(ssdt) str.append("\nAn inline hook rootkit was found. See ssdt scan for more information.\n")
    if(callbacks._1.nonEmpty){
      str.append("\nCallbacks were found on the system indicative of a rootkit\n" )
      str.append("Here are the results we found:\n" + callbacks._1.mkString("\n"))
    }
    if(callbacks._2.nonEmpty){
      str.append("\nThe following calls to APIs commonly used by rootkits were found:\n")
      str.append(callbacks._2.mkString("\n"))
    }
    if(orphan.nonEmpty){
      str.append("\nThe following orphan threads were found that may be indicative of a rootkit:\n" + orphan)
    }
    if(hiddenMods._1.nonEmpty){
      str.append("\nThe following hidden kernel modules were found:\n" + hiddenMods._1.mkString("\n"))
    }
    if(timers.nonEmpty){
      str.append("\nThe following kernel timers were found indicative of a rootkit:\n" + timers.mkString("\n"))
    }

    return str.toString()
  } // END rootkitCheck()

  private[this] def ldrCheck(vec: Vector[LdrInfo]): String = {
    val unlinkedDlls: Vector[Vector[String]] = vec.map(x => x.probs)

    val removeEmptyDlls = unlinkedDlls.filter(x => x.nonEmpty)

    val fixEmpty: Vector[String] = for{
      value <- removeEmptyDlls
    } yield value.mkString(" ")

    val str = if(fixEmpty.nonEmpty) {
      "\nThe following unlinked DLLs were found:\n" + fixEmpty.mkString("\n")
    } else ""

    return str
  } // END ldrCheck()

  private[this] def mappedDrives(vec: Vector[(String, String)]): Vector[String] = {

    val mappedStr = for(value <- vec) yield "PID: " + value._1 + "Drive Information: " + value._2

    return mappedStr
  } // END mappedDrives()

  private[this] def malwareFound(yaraObj: YaraBrain): String = {

    val reportStr = new StringBuilder()
    /** Grab significant yara scan findings */
    val yarMalware: Vector[YaraParseString] = yaraObj.malware
    val yarMal = yarMalware.map(x => (x.proc, x.rule)).distinct
    val malStrVec =  for(value <- yarMal) yield value._1 + " Rule: " + value._2

    if(yarMalware.nonEmpty)
      reportStr.append("\n\t" + malStrVec.mkString("\n\t"))

    val yarSuspicious: YaraSuspicious = yaraObj.suspItems

    /** Malware results. */

    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val antiTup = antidebug.map(x => (x.owner, x.rule)).distinct
    val antidebugVec =  for(value <- antiTup) yield value._1 + " Rule: " + value._2

    if(antidebug.nonEmpty)
      reportStr.append("\nAntidebug tools:\n" + antidebugVec.mkString("\n"))

    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val exploitTup = antidebug.map(x => (x.owner, x.rule)).distinct
    val exploitVec =  for(value <- exploitTup) yield value._1 + " Rule: " + value._2

    if(exploitKits.nonEmpty)
      reportStr.append("\nExploit Kits:\n" + exploitVec.mkString("\n"))

    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val shellsTup = webshells.map(x => (x.owner, x.rule)).distinct
    val shellsVec =  for(value <- shellsTup) yield value._1 + " Rule: " + value._2

    if(webshells.nonEmpty)
      reportStr.append("\nExploit Kits:\n" + shellsVec.mkString("\n"))

    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs
    val docsTup = malDocs.map(x => (x.owner, x.rule)).distinct
    val docsVec =  for(value <- docsTup) yield "Process: " + value._1 + " Rule: " + value._2

    if(malDocs.nonEmpty)
      reportStr.append("\nExploit Kits:\n" + docsVec.mkString("\n"))

    return reportStr.toString
  } // END malwareFound()

  /** This Map of processes was created to avoid the computationally expensive lookup from the main process database.
    * The program will first check this list before looking in the massive database of processes.
    * This list also makes it easier to ensure that the information provided is accurate since it's easy to check.
    */
  private[windows] def commonProcesses(name: String): String = {
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
      "DUMPIT.EXE" -> "Used to create memory dumps",
      "SERVICES.EXE" -> "An essential process that manages the starting and stopping of services including the those in boot up and shut down. Do not terminate it.",
      "SMSS.EXE" -> " Session Manager SubSystem is a system process that is a central part of the Windows operating system.",
      "SPOOLSV.EXE" -> " Microsoft printer spooler service handles local printer processes. It’s a system file.",
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

    return procMap.getOrElse(name, "")
  } // END commonProcesses()

} // END VolatilityIDS object

/****************************************************************************************************/
/****************************************************************************************************/
/*********************************** ProcessDescription Object **************************************/
/****************************************************************************************************/
/****************************************************************************************************/

object ProcessDescription {

  private[windows] def get( processName: String ): String = {

    val firstTwo = Try(processName.take( 2 )).getOrElse("11")

    val byteInt = firstTwo.getBytes()
      .map( x => Try(x.toInt.toString).getOrElse("") )
      .foldLeft( "" )( ( x, y ) => x + y ).toInt

    val tree: TreeMap[String, String] = matchProcess( byteInt )
    val description = tree.getOrElse(processName, "UNKNOWN")

    return description
  } // get()

  /** This is an example of how we'll retrieve the process description. */
  private[this] def matchProcess( value: Int ): TreeMap[String, String] = {

    val result = if (4848 until 6575 contains value) Proc00AK.get()
    else if (6585 until 6682 contains value)  ProcAUBR.get()
    else if (6683 until 6773 contains value)  ProcBSCI.get()
    else if (6774 until 6778 contains value) ProcCJCN.get()
    else if (6779 until 6787 contains value) ProcCOCW.get()
    else if (6787 until 6875 contains value) ProcCXDK.get()
    else if (6876 until 6973 contains value) ProcDLEI.get()
    else if (6974 until 7072 contains value) ProcEJFH.get()
    else if (7073 until 7279 contains value) ProcFIHO.get()
    else if (7280 until 7367 contains value) ProcHPIC.get()
    else if (7368 until 7378 contains value) ProcIDIN.get()
    else if (7379 until 7576 contains value) ProcIOKL.get()
    else if (7577 until 7676 contains value) ProcKMLL.get()
    else if (7677 until 7766 contains value) ProcLMMB.get()
    else if (7767 until 7775 contains value) ProcMCMK.get()
    else if (7776 until 7788 contains value) ProcMLMX.get()
    else if (7789 until 7880 contains value) ProcMYNP.get()
    else if (7881 until 7982 contains value) ProcNQOR.get()
    else if (7983 until 8070 contains value) ProcOSPF.get()
    else if (8071 until 8082 contains value) ProcPGPR.get()
    else if (8083 until 8265 contains value) ProcPRRA.get()
    else if (8266 until 8280 contains value) ProcRBRP.get()
    else if (8281 until 8367 contains value) ProcRRSC.get()
    else if (8368 until 8375 contains value) ProcSDSK.get()
    else if (8376 until 8383 contains value) ProcSLSS.get()
    else if (8384 until 8466 contains value) ProcSTTB.get()
    else if (8467 until 8483 contains value) ProcTCTS.get()
    else if (8484 until 8667 contains value) ProcTTVC.get()
    else if (8668 until 8766 contains value) ProcVDWB.get()
    else if (8767 until 8782 contains value) ProcWCWR.get()
    else if (8783 until 9090 contains value) ProcWSZZ.get()
    else new TreeMap[String, String]()

    return result
  } // END matchProcess()

} // END CreateReport
