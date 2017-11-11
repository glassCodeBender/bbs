package com.bbs.vol.httpclient

import java.net.{HttpURLConnection, URL}
import com.bbs.vol.windows.StringOperations._

import scala.util.Try

final case class PageInfo( name: String,     // registered name
                           city: String,     // city
                           state: String,    // state
                           street: String,   // street
                           country: String,  // country
                           post: String,     // postal cose
                           ipRange: String,  // IP range
                           url: String       // url to see content
                         ){
  override def toString = {
    if (name == "Connection failed.")
      "Connection failed."
    else {
      s"Name: $name/nStreet: $street\nCity: $city\nState: $state\nPostal Code: $post\nCountry: $country\n" +
        s"IP Address Range: $ipRange\nWhois Registration Info URL: $url"
    }
  } // END toString()

} // END PageInfo case class

class WhoIs(ip: String) {

  def query( connectTimeOut: Int = 5000,
             readTimeout: Int = 5000,
             request: String = "GET" ): PageInfo = {

    val url = "http://whois.arin.net/rest/ip/" + ip

    val page = Try(grabPage(url, connectTimeOut, readTimeout, request)).getOrElse("The First Page Failed")

    println("Printing page 1 content...\n")
   // println(page)

    val (url2, netRange): (String, String) = parsePageUrl(page)

    println("Printing next URL...\n")
    println(url2)
    println("Printing IP range...\n")
    println(netRange)

    val infoPage = Try(grabPage(url2, connectTimeOut, readTimeout, request))
      .getOrElse("Connection to second page failed...")

    println("Printing second page content...\n")
    println(infoPage)


    val ipInfo: Vector[String] = parseInfo(infoPage)
    val fullUrl: String = url2 + ".html"

    return PageInfo(ipInfo(0), ipInfo(2), ipInfo(3), ipInfo(1), ipInfo(5), ipInfo(4), netRange, fullUrl)

  } // END query()

  private[this] def parseInfo(page: String): Vector[String] = {


    val city: String = parseCity(page)
    val post: String = parsePost(page)
    val country: String = parseCountry(page)
    val state: String = parseState(page)
    val name: String = parseName(page)
    val street: String = parseStreet(page)

    return Vector(name, street, city, state, post, country )
  } // END parseInfo()

  /** Grab city from XML */
  private[this] def parseCity(page: String): String = {

    val cityReg = "(?<=\\<td\\>City\\</td\\>\\<td\\>).+(?=\\</td\\>".r

    val xml: String = cityReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parseCity()

  /** Grab postal code from XML */
  private[this] def parsePost(page: String): String = {

    //
    val postReg = "\\<td\\>Postal\\s+Code\\</td\\>\\<td\\>.+\\</td\\>".r

    val xml: String = postReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parsePost()

  /** Grab country from XML */
  private[this] def parseCountry(page: String): String = {

    val countryReg = "(?<=\\<td\\>Country\\</td\\>\\<td\\>).+(?=\\</td\\>)".r

    // <td>Country</td><td>US</td>
    val xml: String = countryReg.findFirstIn(page).getOrElse("Connection failed.")

    //val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    //val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return xml
  } // END parseCity()

  /** Grab state from XML */
  private[this] def parseState(page: String): String = {

    // <td>State/Province</td><td>CA</td>
    val stateReg = "(?<=\\<State/{Province\\</td\\<td\\>).+(?=/td\\>)".r
    val xml: String = stateReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parsePost()

  /** Grab name from XML */
  private[this] def parseName(page: String): String = {

    // <td>Name</td><td>MARKETO</td>
    val nameReg = """(?<=<td>Name</td><td>).+(?=</td>)""".r

    val xml: String = nameReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parseCity()

  /** Grab street from XML */
  private[this] def parseStreet(page: String): String = {
    val streetReg = "(?<=<td>Street</td><td>).+(?=<br>)".r

    val xml: String = streetReg.findFirstIn(page).getOrElse("Connection failed.")

    println("\n\nPrinting parsed streets: " + xml)
    return xml
  } // END parsePost()

  /** Grab URL for the next page so we can find info about IP address. */
  private[this] def parsePageUrl(page: String): (String, String) = {

    /** Grab xml content from first page */

    val regex = """(?<=<td>Organization<.+\(<a\s+href=").+(?=")""".r

    // "(?<=\\<).*(?=\\>)".r
    // <td>Net Range</td><td>131.107.0.0 - 131.107.255.255</td>

    // Grab net
    val netReg = """(?<=<Net\s+Range</td><td>).+(?=>)""".r

    val xml: String = regex.findFirstIn(page).getOrElse("Connection failed.")

    println("\n\nPrint address range: " + xml)

    val addr = netReg.findFirstIn(page).getOrElse("Connection failed.")
    
    println("\n\nPrinting Address Range: " + addr)

    return (xml, addr)
  } // END parsePage()

  /** Get web page */
  private[this] def grabPage(url: String,
                  connectTime: Int,
                  readTime: Int,
                  request: String): String = {
    val connection = new URL(url).openConnection.asInstanceOf[HttpURLConnection]

    connection.setConnectTimeout(connectTime)
    connection.setReadTimeout(readTime)
    connection.setRequestMethod(request)

    val inputStream = connection.getInputStream
    val webPage: String = io.Source.fromInputStream(inputStream).mkString
    if (inputStream == null) inputStream.close()

    return webPage
  } // END grabPage()

} // END WhoIs
