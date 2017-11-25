package com.bbs.vol.httpclient

import com.bbs.vol.utils.FileFun

import scala.util.Try

/**
  * Program grabs a description of a DLL if the DLL was not found in process tree.
  * Appends to file so I can use later.
  */

object GetDllDescription extends HttpClient with FileFun {

  private[vol] def run(dllName: String): String = {

    val name = dllName.toLowerCase()

    val page = Try(queryPage(s"http://dllsearch.net/search?s=$name&ss=Search")).getOrElse("")

    val description = parsePage(page, dllName)

    val forTree = "\"" + dllName.toUpperCase() + "\"" + " -> " + "\"" + description + "\""

    /** Append description to file I'll use to manually put entries in proctree. */
    val fileName = System.getProperty("user.dir") + "/dll_descriptions.txt"
    if(description.nonEmpty) appendToFile(fileName, forTree)

    return description
  } // END run()

  /** Get DLL Description from page */
  private[this] def parsePage(page: String, dllName: String): String = {

    val splitAlphabetical = Try(page.split("""alphabetical""")(1)).getOrElse("")
    val splitName = Try(splitAlphabetical.split(page)(1)).getOrElse("")
    val splitDd = Try(splitName.split("""<dd>""")(1)).getOrElse("")
    val description = Try(splitDd.split("""</dd>""")(0)).getOrElse("")

    return description
  } // END parsePage()

} // END
