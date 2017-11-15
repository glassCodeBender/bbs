package com.bbs.vol.windows

object CreateReport {

  def run(memFile: String, os: String, process: ProcessBrain, disc: Discovery, riskRating: Int) = {
    /** Using StringBuilder for fast concatenation of Strings. */
    val report = new StringBuilder()

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

    if(malware.nonEmpty) report.append("\tMalware Found: None")

    report.append(malware)
    report.append("Significant Findings:\n\n")

    /**\tDisabled Services */
    if(svc.nonEmpty) report.append("\tThe following suspicious services were disabled.\n\t" + svc.mkString("\n\t"))

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

    /** \tMemory Leaks*/

    /** Suspicious Console Commands */

    /** PROCESS INFO */


  } // END run()

  /*****************************************************************
    * **************************************************************
    * **************Results Summary Section ************************
    * **************************************************************
    ****************************************************************/
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

    if(yarMalware.nonEmpty) reportStr.append("\n\t" + malStrVec.mkString("\n\t"))

    val yarSuspicious: YaraSuspicious = yaraObj.suspItems

    /** Malware results. */

    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val antiTup = antidebug.map(x => (x.owner, x.rule))
    val antidebugVec =  for(value <- antiTup) yield value._1 + " Rule Found: " + value._2
    if(antidebug.nonEmpty) reportStr.append("\n\tAntidebug tools:\n\t" + antidebugVec.mkString("\n\t"))

    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val exploitTup = antidebug.map(x => (x.owner, x.rule))
    val exploitVec =  for(value <- exploitTup) yield value._1 + " Rule Found: " + value._2
    if(exploitKits.nonEmpty) reportStr.append("\n\tExploit Kits:\n\t" + exploitVec.mkString("\n\t"))

    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val shellsTup = webshells.map(x => (x.owner, x.rule))
    val shellsVec =  for(value <- shellsTup) yield value._1 + " Rule Found: " + value._2
    if(webshells.nonEmpty) reportStr.append("\n\tExploit Kits:\n\t" + shellsVec.mkString("\n\t"))

    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs
    val docsTup = malDocs.map(x => (x.owner, x.rule))
    val docsVec =  for(value <- docsTup) yield "Process: " + value._1 + " Rule Found: " + value._2
    if(malDocs.nonEmpty) reportStr.append("\n\tExploit Kits:\n\t" + docsVec.mkString("\n\t"))
    
    return reportStr.toString
  } // END malwareFound()
} // END CreateReport
