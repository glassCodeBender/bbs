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

    val page = grabPage(url, connectTimeOut, readTimeout, request)

    println("Printing page 1 content...\n")
    println(page)

    val page1Info = parsePageUrl(page)

    println("Printing next URL...\n")
    page1Info.foreach(println)

    val infoPage = Try(grabPage(page1Info(0), connectTimeOut, readTimeout, request))
      .getOrElse("Connection to second page failed...")

    println("Printing second page content...\n")
    println(infoPage)

    /** Stores start ip address and end ip address */
    val addressRange: String = page1Info(1) + "-" + page1Info(2)

    val ipInfo: Vector[String] = parseInfo(infoPage)
    val fullUrl: String = page1Info(0) + ".html"

    return PageInfo(ipInfo(0), ipInfo(2), ipInfo(3), ipInfo(1), ipInfo(5), ipInfo(4), addressRange, fullUrl)

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
    val cityReg = "<city.+city>".r

    val xml: String = cityReg.findFirstIn(page).getOrElse("Connection failed.")

    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return lastSplit
  } // END parseCity()

  /** Grab postal code from XML */
  private[this] def parsePost(page: String): String = {
    val postReg = "<postalCode.+postalCode>".r

    val xml: String = postReg.findFirstIn(page).getOrElse("Connection failed.")

    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return lastSplit
  } // END parsePost()

  /** Grab country from XML */
  private[this] def parseCountry(page: String): String = {
    val countryReg = "<code3.+code3>".r

    val xml: String = countryReg.findFirstIn(page).getOrElse("Connection failed.")

    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return lastSplit
  } // END parseCity()

  /** Grab state from XML */
  private[this] def parseState(page: String): String = {
    val stateReg = "<iso3166\\-.+iso3166\\-2>".r
    val xml: String = stateReg.findFirstIn(page).getOrElse("Connection failed.")

    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return lastSplit
  } // END parsePost()

  /** Grab name from XML */
  private[this] def parseName(page: String): String = {
    val nameReg = "handle><name.+name>".r

    val xml: String = nameReg.findFirstIn(page).getOrElse("Connection failed.")
    val splitX: String = Try(xml.split('<')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('>')(1)).getOrElse("Connection failed.")
    val finalSplit: String = Try(lastSplit.split('<')(0)).getOrElse("Connection failed.")

    return finalSplit
  } // END parseCity()

  /** Grab street from XML */
  private[this] def parseStreet(page: String): String = {
    val streetReg = "line.+streetAddress>".r

    val xml: String = streetReg.findFirstIn(page).getOrElse("Connection failed.")
    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    return lastSplit
  } // END parsePost()

  /** Grab URL for the next page so we can find info about IP address. */
  private[this] def parsePageUrl(page: String): Vector[String] = {

    /** Grab xml content from first page */

    /** Grab Url page */
    val regex = "<orgRef.+orgRef>".r
    /** Grab start ip */
    val startReg = "<startAddress.+startAddress>".r
    /** Grab end ip */
      val endReg = "<endAddress.+endAddress>".r

    val xml: String = regex.findFirstIn(page).getOrElse("Connection failed.")

    val splitX: String = Try(xml.split('>')(1)).getOrElse("Connection failed.")
    val lastSplit: String = Try(splitX.split('<')(0)).getOrElse("Connection failed.")

    val xmlStart = startReg.findFirstIn(page).getOrElse("Connection failed.")
    val xmlEnd = endReg.findFirstIn(page).getOrElse("Connection failed.")

    val splitBegin = Try(xmlStart.split('>')(1)).getOrElse("Connection failed.")
    val start = Try(splitBegin.split('<')(0)).getOrElse("Connection failed.")

    val splitEnd: String = Try(xmlEnd.split('>')(1)).getOrElse("Connection failed.")
    val end: String = Try(splitEnd.split('<')(0)).getOrElse("Connection failed.")

    return Vector(lastSplit, start, end)
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
    if (inputStream == null) inputStream.close

    return webPage
  } // END grabPage()

} // END WhoIs
