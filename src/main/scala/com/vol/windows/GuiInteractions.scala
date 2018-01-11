package com.bbs.vol.windows

import scala.util.Try
import sys.process._

object GuiInteractions extends VolParse {

  private[windows] def run(memFile: String, os: String, kdbg: String) = {

    /** Vector of PIDs that were launched via RDP. */
    val rdpPids = examineSessions(memFile, os, kdbg)



  } // END run()

  /**
    * examineSession()
    * Description: Checks in RDP session occurred.
    * @return Vector[String] made up of PIDs launched over session.
    * @param memFile
    * @param os
    * @param kdbg
    *
    */
  private[this] def examineSessions(memFile: String, os: String, kdbg: String): Vector[String] = {

    val sessions = if(kdbg.nonEmpty){
      Try( s"python vol.py --conf-file=user_config.txt sessions".!!.trim ).getOrElse("")
    }else {
      Try(s"python vol.py -f $memFile --profile=$os session".!!.trim).getOrElse("")
    }

    val sessionsArr: Vector[String] = parseOutputNoTrim(sessions).getOrElse(Vector[String]())

    // rdpclip.exe handles remote clipboard operations.
    val rdpClip = sessionsArr.filter(x => x.toLowerCase.contains("rdpclip.exe"))
    // rdpdd.dll is the RDP display driver.
    val rdpDll = sessionsArr.filter(x => x.toLowerCase.contains("rdpdd.dll"))

    val pidRegex = "\\d+".r

    /** Vector of PIDs that were launched via RDP. */
    val rdpPidLaunched = if(rdpClip.nonEmpty || rdpDll.nonEmpty){
      sessionsArr.filter(x => x.toLowerCase.contains("process"))
        .map(x => pidRegex.findFirstIn(x).getOrElse(""))
    } else{
      Vector("")
    }

    return rdpPidLaunched
  } // END examineSessions()

} // END GuiInteractions object
