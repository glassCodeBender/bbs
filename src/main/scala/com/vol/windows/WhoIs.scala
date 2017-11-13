package com.bbs.vol.httpclient

import java.net.{HttpURLConnection, URL}
// import com.bbs.vol.windows.StringOperations._

import scala.util.Try

final case class PageInfo( ip: String, 
                           name: String,     // registered name
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
      s"\nWhois Results for $url\nName: $name\nStreet: $street\nCity: $city\nState: $state\nPostal Code: $post\nCountry: $country\n" +
        s"IP Address Range: $ipRange\nWhois Registration Info URL: $url" + "\n"
    }
  } // END toString()

} // END PageInfo case class

class WhoIs(ip: String) {

  def query( connectTimeOut: Int = 5000,
             readTimeout: Int = 5000,
             request: String = "GET" ): PageInfo = {

    val url = "http://whois.arin.net/rest/ip/" + ip

    println("Querying with whois at url: " + url + "\n")
    val page = grabPage(url, connectTimeOut, readTimeout, request)

    val (url2, netRange): (String, String) = parsePageUrl(page)

    val infoPage = Try(grabPage(url2, connectTimeOut, readTimeout, request))
      .getOrElse("Connection to second page failed...")

    val ipInfo: Vector[String] = parseInfo(infoPage)

    return PageInfo(ip, ipInfo(0).trim, ipInfo(2).trim, ipInfo(3).trim,
      ipInfo(1).trim, ipInfo(5).trim, ipInfo(4).trim, netRange, url2)
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

    // val cityReg = "(?<=\\<td\\>City\\</td\\>\\<td\\>).{1,20}(?=\\</td\\>".r

    val splitOne = Try(page.split("""<td>City</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")

    // val xml: String = cityReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parseCity()

  /** Grab postal code from XML */
  private[this] def parsePost(page: String): String = {

    // val postReg = "\\<td\\>Postal\\s+Code\\</td\\>\\<td\\>.{1,20}\\</td\\>".r

    val splitOne = Try(page.split("""Code</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")

    // val xml: String = postReg.findFirstIn(page).getOrElse("Connection failed.")

    return xml
  } // END parsePost()

  /** Grab country from XML */
  private[this] def parseCountry(page: String): String = {

    // val countryReg = "(?<=\\<td\\>Country\\</td\\>\\<td\\>).{1,20}(?=\\</td\\>)".r

    val splitOne = Try(page.split("""<td>Country</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")

    return xml
  } // END parseCity()

  /** Grab state from XML */
  private[this] def parseState(page: String): String = {

    val splitOne = Try(page.split("""<td>State/Province</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")

    return xml
  } // END parsePost()

  /** Grab name from XML */
  private[this] def parseName(page: String): String = {

    val splitOne = Try(page.split("""<td>Name</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")

    return xml
  } // END parseCity()

  /** Grab street from XML */
  private[this] def parseStreet(page: String): String = {

    val splitOne = Try(page.split("""<td>Street</td><td>""")(1)).getOrElse("Failed")
    val xml = Try(splitOne.split("""</td>""")(0)).getOrElse("Failed")
    val finalX = Try(xml.split("""<br>""")(0)).getOrElse("Failed")

    return finalX
  } // END parsePost()

  /** Grab URL for the next page so we can find info about IP address. */
  private[this] def parsePageUrl(page: String): (String, String) = {

    /** Grab xml content from first page */
    val firstSplit = Try(page.split("""Organization""")(1)).getOrElse("Split fail")
    val secondSplit = Try(firstSplit.split('\"')(1)).getOrElse("Split fail")
    val href = Try(secondSplit.split('\"')(0)).getOrElse("Split fail")

    val range = Try(page.split("""Range</td><td>""")(1)).getOrElse("Connection failed.")
    println("Printing split one result: " + range)
    val finalRange = Try(range.split("""</td>""")(0)).getOrElse("Connection failed.")

    return (href.trim, finalRange.trim)
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
