package com.bbs.vol.windows

import com.bbs.vol.processtree._
import com.bbs.vol.utils.FileFun

import scala.collection.immutable.TreeMap

object CreateReport extends FileFun {

  private[windows] def run(memFile: String, os: String, process: ProcessBrain, disc: Discovery, riskRating: Int) = {
    /** Using StringBuilder for fast concatenation of Strings. */
    val report = new StringBuilder()

    /**
      *
      */

    /** Grab info we need for report. */
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
    val svc = sysSt.svcStopped

    val net: Vector[NetConnections] = disc.net._1

    /**
      * Get info from ProcessBrain
      */
    val yaraObj: YaraBrain = process.yara
    val regPersist: Vector[RegPersistenceInfo] = process.regPersistence // done
    val ldr: Vector[LdrInfo] = process.ldrInfo // done
    val privs: Vector[Privileges] = process.privs // done

    val promiscModeMap: Map[String, Boolean] = process.promiscMode

    /** Write Report */
    val intro = s"Big Brain Security Volatile IDS Report for $memFile\n\nSummary:\n\n\tRisk Rating: $riskRating\n\n"
    report.append(intro + "\tMalware Found: \n\n")

    /** Yara malware findings */
    val malware: String = malwareFound(yaraObj)

    if(malware.nonEmpty)
      report.append("\tMalware Found: None")

    report.append(malware)
    report.append("Significant Findings:\n\n")

    /**\tDisabled Services */
    if(svc.nonEmpty)
      report.append("\tThe following suspicious services were disabled.\n\t" + svc.mkString("\n\t"))

    /**\tRemote Mapped Drives */
    val mappedDriveVec = mappedDrives(remoteMapped)
    if(mappedDriveVec.nonEmpty){
      report.append("\n\tThe following remote mapped drives were found:\n\t" + mappedDriveVec.mkString("\n\t"))
    }

    /** \tUnlinked DLLs*/
    val ldrInfoCheck = ldrCheck(ldr)

    report.append(ldrInfoCheck)

    /**\tRootkits Found */
    val rootkitInfo = rootkitCheck(rootkit)

    report.append(rootkitInfo)

    /** \tPromiscuous Mode*/
    if(promiscModeMap.nonEmpty) {
      report.append("\n\tThe system was put into promiscuous mode by the following pid(s): " + promiscModeMap.keys.mkString(", "))
    }

    /** \tHidden Processes*/
    val hiddenStr: String = hiddenProcs(proc)
    if(hiddenStr.nonEmpty){
      report.append("\n\tThe following hidden processes were found:\n\t" + hiddenStr)
      report.append("\n\tNOTE: If the processes, is not used by anti-virus software, you have malware.")
    }

    /** Whether or not VNC is on the system. */
    val vnc = vncCheck(net)
    if(vnc.nonEmpty) report.append(vnc)

    /** \tMeterpreter DLL */
    val meterpreter = checkMeterpreter(ldr)
    if(meterpreter.nonEmpty)
      report.append(meterpreter)

    /** \tMemory Leaks*/
    val leaks = memoryLeaks(regPersist)
    if(leaks.nonEmpty)
      report.append(leaks)

    /** Run findHiddenExecs() and say if any execs were found. */
    val hiddenExec = findHiddenExecs(proc)
    if(hiddenExec.nonEmpty)
      report.append(hiddenExec)

    /** Suspicious Console Commands */
    if(sysSt.suspCmds.nonEmpty){
      report.append("\n\tThe following potentially suspicious exams were found in the commandline info: \n\t")
      report.append(sysSt.suspCmds.mkString("\n\t"))
    }

    /** Commandline History */
    if(sysSt.consoles.nonEmpty){
      report.append("Commandline History Found:\n\n")
      report.append(sysSt.consoles)
    }

    /** PROCESS INFO */

    val procTree = disc.proc._2
    report.append("\nProcess Tree Results:\n\n" + procTree )

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
      "context into what they are examining. Malicious code can be injected into a process. Do not assume that " +
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

    val ppidVec = procInfo.filter(x => x.ppid.contains(proc.pid))
    var ppidName = ""

    if(ppidVec.nonEmpty)
      ppidName = ppidVec.head.ppid

    report.append("Name: " + proc.name + "  PID: " + proc.pid )

    if(ppidName.nonEmpty)
      report.append("\nParent Name: " + ppidName)

    if(description.nonEmpty)
      report.append("\nDescription: " + description)

    if(proc.hidden)
      report.append("\nHidden: True")

    /** Check if metepreter dll was found in process or in parent. */
    val ldrPid = ldr.filter(x => x.pid.contains(proc.pid))
    val ldrPpid = ldr.filter(x => x.pid.contains(proc.ppid))

    if(ldrPid.nonEmpty){
      val ldr = ldrPid.head
      if(ldr.meterpreter)
        report.append("\nMeterpreter DLL Found: True!!!!!!")
    }
    if(ldrPpid.nonEmpty){
      val ldr = ldrPpid.head
      if(ldr.meterpreter)
        report.append(s"\nMeterpreter DLL Found in Parent Process $ppidName: True!!!!!!")
    }

    /** Add Dll command found */
    val dll: Vector[DllInfo] = procBrain.dllInfo
    val dllPerPid = dll.filter(x => x.pid.contains(proc.pid))
    var dllCommand = ""

    if(dllPerPid.nonEmpty)
      dllCommand =  dllPerPid.head.command
    if(dllCommand.nonEmpty)
      report.append("\nCommandline Info: " + dllCommand)

    /** Check yara for malicious signatures found  */
    val checkYaraPid = checkYaraPerProcess(proc.pid, yara)
    val checkYaraPpid = checkYaraPerProcess(proc.ppid, yara)

    if(checkYaraPid.nonEmpty)
      report.append("\nMalicious Signatures Found in Process:" + checkYaraPid)
    if(checkYaraPpid.nonEmpty)
      report.append("\nMalicious Signatures Found in Parent Process:" + checkYaraPpid)

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
          report.append("\n\nRegistry Persistence Info For Current Process: " + ppidPersistence.head)
        } // END if registry persistence exists
      if (ppidResult.getOrElse("0") != "0") {
          report.append(s"\n\nRegistry Persistence Info For Parent Process $ppidName PID ${proc.ppid}: " + ppidPersistence.head)
      } // END if persistMap exists
    } // END persistenceMap.nonEmpty

    /** Add information about privileges */
    val privs = procBrain.privs
    val priv = privs.filter(x => x.pid.contains(proc.pid))

    if(priv.nonEmpty) {
      val privResult = priv.head

      if(privResult.debugPriv){
        report.append("\nDebug Privilege was explicitly enabled. Attackers commonly do this.\n\n")
        report.append("Suspicious Privileges:\n" + priv.head.suspiciousPrivs.mkString("\n"))
      }

      if(privResult.enabledPrivs.nonEmpty) {
        report.append("The following privileges were explicitly enabled:\n" +
          privResult.enabledPrivs.mkString("\n"))
      }

    } // END priv nonEmpty

    /** Networking capability */
    // val netActivityMap = procBrain.netActivity

    // if(netActivityMap(proc.pid))report.append("\nNetworking Activity: True")
    //else report.append("\nNetworking Activity: Unknown")

    /** Add information about outside ip addresses */
    val connections = netActivity(disc.net._1, proc.pid)
    if(connections.nonEmpty) report.append(connections)

    /** Malfind Results */
    val malfind = procBrain.malfind.getOrElse(proc.pid, "")
    val ppidMalfind = procBrain.malfind.getOrElse(proc.ppid, "")

    if(malfind.nonEmpty)
      report.append("\nMalfind found the following results for " + proc.name + s"\n\n$malfind")
    if(ppidMalfind.nonEmpty)
      report.append(s"\nMalfind found the following results for the parent of ${proc.name}: $ppidName PID ${proc.ppid}\n\n$ppidMalfind")

    val urls = checkYaraLessImportant(yara, proc.pid)

    if(urls.nonEmpty) report.append(urls)

    report.append("\n*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*\n\n")

    return report.toString
  } // writeEachProcess()

  private[this] def netActivity(vec: Vector[NetConnections], pid: String): String = {
    var str = ""
    val pids = vec.filter(x => x.pid.contains(pid))
    val srcIps = pids.map(x => x.srcIP)
    val destIps = pids.map(x => x.destIP)
    /** Removing local ip addresses */
    val srcFiltered = {
      srcIps.filterNot(_.startsWith("192\\.")).filterNot(_.startsWith("172\\.")).filterNot(_.startsWith("10\\."))
    }
    val destFiltered = {
      destIps.filterNot(_.startsWith("192\\.")).filterNot(_.startsWith("172\\.")).filterNot(_.startsWith("10\\."))
    }
    if(srcFiltered.nonEmpty){
      str = "\nThe following external source IP addresses were found:\n" + srcFiltered.mkString("\n")
    }
    if(destFiltered.nonEmpty){
      str = str + "\nThe following external destination IP addresses were found:\n" + destFiltered.mkString("\n")
    }

    return str
  } // END netActivity()


  /** Grab Yara info from processes */
  private[this] def checkYaraPerProcess(pid: String, yara: YaraBrain): String = {
    val report = new StringBuilder()

    if(pid == "0")""
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
      val pidMal = malware.filter(x => x.proc.contains(pid))
      // val pidSuspStr = susStr.filter(x => x.proc.contains(pid))
      val pidMalDoc = malDoc.filter(x => x.owner.contains(pid))
      val pidShells = shells.filter(x => x.owner.contains(pid))
      val pidAnti = antidebug.filter(x => x.owner.contains(pid))
      val pidCVE = cve.filter(x => x.owner.contains(pid))
      val pidPack = pack.filter(x => x.owner.contains(pid))
      val pidExploit = exploitkits.filter(x => x.owner.contains(pid))

      /** Append to StringBuilder if found */
      if (pidMal.nonEmpty)
        report.append("\n\nMalware Signatures Found:\n\n" + pidMal.mkString("\n"))
      if (pidAnti.nonEmpty)
        report.append("\n\nAntidebug Signatures Found:\n\n" + pidAnti.mkString("\n"))
      if (pidCVE.nonEmpty)
        report.append("\n\nCVEs(Malware) Found:\n\n" + pidCVE.mkString("\n"))
      if (pidExploit.nonEmpty)
        report.append("\n\nExploit Kits Found:\n\n" + pidExploit.mkString("\n"))
      if (pidShells.nonEmpty)
        report.append("\n\nWebshells Found:\n\n" + pidShells.mkString("\n"))
      if (pidMalDoc.nonEmpty)
        report.append("\n\nMalicious Documents Found:\n\n" + pidMalDoc.mkString("\n"))
      if (pidPack.nonEmpty)
        report.append("\n\nPackers Found:\n\n" + pidPack.mkString("\n"))
      // if(pidSuspStr.nonEmpty)""
      report.toString()
    }

  } // END checkYaraPerProcess()

  private[this] def checkYaraLessImportant(yara: YaraBrain, pid: String): String = {
    var str = ""
    val urls = yara.url
    val pidUrls = urls.filter(x => x.proc.contains(pid))
    if(pidUrls.nonEmpty)str = "\n\nURLs Found By Yara:\n" + pidUrls.mkString("\n")

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
      println("\nPrinting hidden executables.\n\n")
      hiddenProcs.foreach(println)
      str = str + "\n\tThe following hidden processes were found:\n\t" + hiddenProcs.mkString("\n\t")
    } // END if nonEmpty
    
    return str
  } // END hiddenExecPattern

  /** Check for meterpreter DLL */
  private[this] def checkMeterpreter(vec: Vector[LdrInfo]) = {
    var str = ""
    val meter = vec.map(x => (x.pid, x.meterpreter))
    val meterFound = meter.filter(x => x._2 == true)
    if(meterFound.nonEmpty) {
      str = "\n\tA DLL used by meterpreter was found on the system indicating that the system was breached."
      val dllFound = for(value <- meterFound) yield s"\n\tA meterpreter DLL was found in PID: ${value._1}"
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
      reportStr = "\n\tDuplicate run keys are an indication that an attacker used the registry to establish persistence.\n"
      tempVec = for(values <- filterCount) yield s"\t${values._2} links to the run key were found in PID: ${values._1}"
      reportStr = reportStr + tempVec.mkString("\n")

      if(filterCount.exists(x => x._2 > 8)) {
        reportStr = reportStr + {
          s"\n\n\tWe have determined that an attacker used the run key to establish registry persistence.\n"
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
      str = "\n\tVNC was found on the system. This is remote desktop software commonly used for malicious and non-malicious reasons.\n\t" +
      vncCheck.mkString("\n\t")
    }
    return str
  } // END vncCheck()

  private[this] def hiddenProcs(procs: Vector[ProcessBbs]): String = {
    val hidden: Vector[String] = for{
      value <- procs
      if value.hidden == true
    } yield "PID: " + value.pid + "Name: " + value.name

    val str = hidden.mkString("\n\t")

    return str
  } // END hiddenProcs()

  private[this] def rootkitCheck(root: RootkitResults): String = {
    val str = new StringBuilder()
    val callbacks = root.callbacks        // done
    val hiddenMods = root.hiddenModules   // done
    val orphan: String = root.orpanThread // done
    val timers = root.timers              // done
    val ssdt = root.ssdtFound // done

    if(ssdt) str.append("\n\tAn inline hook rootkit was found. See ssdt scan for more information.\n\t")
    if(callbacks._1.nonEmpty){
      str.append("\n\tCallbacks were found on the system indicative of a rootkit\n\t" )
      str.append("Here are the results we found:\n\t" + callbacks._1.mkString("\n\t"))
    }
    if(callbacks._2.nonEmpty){
      str.append("\n\tThe following calls to APIs commonly used by rootkits were found:\n\t")
      str.append(callbacks._2.mkString("\n\t"))
    }
    if(orphan.nonEmpty){
      str.append("\n\tThe following orphan threads were found that may be indicative of a rootkit:\n\t" + orphan)
    }
    if(hiddenMods._1.nonEmpty){
      str.append("\n\tThe following hidden kernel modules were found:\n\t" + hiddenMods._1.mkString("\n\t"))
    }
    if(timers.nonEmpty){
      str.append("\n\tThe following kernel timers were found indicative of a rootkit:\n\t" + timers.mkString("\n\t"))
    }

    return str.toString()
  } // END rootkitCheck()

  private[this] def ldrCheck(vec: Vector[LdrInfo]): String = {
    val unlinkedDlls = vec.map(x => x.probs)
    var str = ""
    if(unlinkedDlls.nonEmpty) {
      str = "\n\tThe following unlinked DLLs were found:\n\t" + unlinkedDlls.mkString("\n\t")
    }

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
    val yarMal = yarMalware.map(x => (x.proc, x.rule))
    val malStrVec =  for(value <- yarMal) yield value._1 + " Rule Found: " + value._2

    if(yarMalware.nonEmpty)
      reportStr.append("\n\t" + malStrVec.mkString("\n\t"))

    val yarSuspicious: YaraSuspicious = yaraObj.suspItems

    /** Malware results. */

    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val antiTup = antidebug.map(x => (x.owner, x.rule))
    val antidebugVec =  for(value <- antiTup) yield value._1 + " Rule Found: " + value._2

    if(antidebug.nonEmpty)
      reportStr.append("\n\tAntidebug tools:\n\t" + antidebugVec.mkString("\n\t"))

    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val exploitTup = antidebug.map(x => (x.owner, x.rule))
    val exploitVec =  for(value <- exploitTup) yield value._1 + " Rule Found: " + value._2

    if(exploitKits.nonEmpty)
      reportStr.append("\n\tExploit Kits:\n\t" + exploitVec.mkString("\n\t"))

    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val shellsTup = webshells.map(x => (x.owner, x.rule))
    val shellsVec =  for(value <- shellsTup) yield value._1 + " Rule Found: " + value._2

    if(webshells.nonEmpty)
      reportStr.append("\n\tExploit Kits:\n\t" + shellsVec.mkString("\n\t"))

    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs
    val docsTup = malDocs.map(x => (x.owner, x.rule))
    val docsVec =  for(value <- docsTup) yield "Process: " + value._1 + " Rule Found: " + value._2

    if(malDocs.nonEmpty)
      reportStr.append("\n\tExploit Kits:\n\t" + docsVec.mkString("\n\t"))

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
    val firstTwo = processName.take( 2 )
    val byteInt = firstTwo.getBytes()
      .map( x => x.toInt.toString ).foldLeft( "" )( ( x, y ) => x + y ).toInt

    val tree: TreeMap[String, String] = matchProcess( byteInt )
    val description = tree.getOrElse(processName, "")

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

} // END CreateReport
