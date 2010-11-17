using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Exchange.Data.Transport;
using Microsoft.Exchange.Data.Transport.Smtp;
using System.Net.Sockets;
using System.IO;

//email URL regex (group 0 is domain)
//http\://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3})(/\S*)?

//WHOIS creation regex (group 0 is date, seems to always be in format dd-3 letter month-yyyy
//Creat[^:]*:\s*([^\s]*)

namespace MetroparkAgents
{
    public sealed class MetroparkAgentFactory : SmtpReceiveAgentFactory
    {
        public override SmtpReceiveAgent CreateAgent(SmtpServer server)
        {
            return new YoungDomainSpamAgent();
        }
    }

    public class YoungDomainSpamAgent : SmtpReceiveAgent
    {
        const string url_regex = "http\\://([a-zA-Z0-9\\-\\.]+\\.)*([a-zA-Z0-9\\-]+\\.[a-zA-Z]{2,4})(/\\S*)?";
        const string creation_regex = "Creat[^:]*:\\s*([^\\s]*)";
        const bool use_whois_servers_net = true;
        const string static_whois_server = "whois.arin.net";

        public string GetWhoisServer( string tld )
        {
            if (use_whois_servers_net)
            {
                return tld + ".whois-servers.net";
            }
            else
                return static_whois_server;
        } 

        const string log_file = "C:\\metropark_agents\\yds.log";
        const int minimum_age = 200; //Age, in days, a domain must exist to no be considered 'young'
        Dictionary<string, bool> known_domains = new Dictionary<string,bool>();
        int blocked = 0;
        int whois_errors = 0;
        int cached_hits = 0;

        private static SmtpResponse silentRejectResponse =
            new SmtpResponse("250", "", "OK");

        private static SmtpResponse normalRejectResponse =
            new SmtpResponse("500", "", "Message rejected - yds");

        public YoungDomainSpamAgent()
        {
            this.OnEndOfData += new EndOfDataEventHandler(
                this.OnEndOfDataHandler);
            known_domains.Add("microsoft.com", false);
            known_domains.Add("w3c.org", false);
            known_domains.Add("w3.org", false);
            known_domains.Add("yahoo.com", false);
            known_domains.Add("gmail.com", false);
            known_domains.Add("google.com", false);
            known_domains.Add("facebook.com", false);
            System.Data.SQLite.
        }

        private void OnEndOfDataHandler(
            ReceiveMessageEventSource source,
            EndOfDataEventArgs e)
        {
            string bodyAsText = "";
            StreamReader reader = new StreamReader(e.MailItem.Message.Body.GetContentReadStream(), Microsoft.Exchange.Data.Globalization.Charset.GetEncoding(e.MailItem.Message.Body.CharsetName), true);
            bodyAsText = reader.ReadToEnd();
            reader.Close();

            if (this.ShouldBlockMessage(bodyAsText, e.MailItem.Message.Subject))
            {
                source.RejectMessage(
                    this.GetRejectResponse());
            }
        }

        private static void DebugLog(string what)
        {
            try
            {
                StreamWriter SW;
                SW = File.AppendText(log_file);
                SW.WriteLine(DateTime.Now.ToUniversalTime() + "\n---------------------------\n\t" + what + "\n\n");
                SW.Close();
            }
            catch (Exception ex)
            {
                System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "Could not write to log: " + log_file + "\n" + ex.Message, System.Diagnostics.EventLogEntryType.Error);
            }
        }

        private bool ShouldBlockMessage(string body, string subject)
        {
            // TODO: put logic here to decide whether to block 
            // the message.
            Regex rx = new Regex(url_regex);
            MatchCollection mc = rx.Matches(body);

            foreach( Match submatch in mc )
            {
                if (IsYoungDomain(submatch.Groups[2].ToString()))
                {
                    DebugLog("Message blocked! Subject:\"" + subject + "\" Domain: " + submatch.Groups[2].ToString());
                    blocked++;
                    if (blocked % 100 == 0)
                    {
                        System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "Messages blocked so far: " + blocked + "\nErrors: " + whois_errors + "\nCached hits: " + cached_hits, System.Diagnostics.EventLogEntryType.Information);
                    }
                    return true;
                }
            }

            return false;
        }

        private SmtpResponse GetRejectResponse()
        {
            bool silentReject = false;

            // TODO: put logic here to decide which response to use.

            return
                silentReject
                ? YoungDomainSpamAgent.silentRejectResponse
                : YoungDomainSpamAgent.normalRejectResponse;
        }

        private bool IsYoungDomain(string domain_name)
        {
            string response = "";
            if (known_domains.ContainsKey( domain_name) )
            {
                cached_hits++;
                return known_domains[domain_name];

            }

            try
            {
                //TODO: Consider throwing exception if whois fails...

                if (DoWhoisLookup(domain_name, out response))
                {
                    Regex rx = new Regex(creation_regex);
                    Match created_match = rx.Match(response);
                    if (created_match.Success)
                    {
                        DateTime created = DateTime.Parse(created_match.Groups[1].ToString());
                        TimeSpan age = DateTime.Now - created;

                        if (age.Days < minimum_age)
                        {
                            known_domains[domain_name] = true;
                            return true;
                        }
                        else
                            known_domains[domain_name] = false;
                    }
                    else if (response.ToLower().Contains("no match for") || response.ToLower().Contains("not found:") )
                    {  //This clause may be a bad thing...
                        known_domains[domain_name] = true;
                        return true;
                    }
                    else
                    {
                        DebugLog("Could not match created Date for domain " + domain_name + ": \n" + response);
                    }

                }
            }
            catch (Exception e)
            {
                System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "DateTime " + response, System.Diagnostics.EventLogEntryType.Error);
                whois_errors++;
            }

            return false;

        }

        private string GetTLD(string domain_name)
        {
            Regex tld_regex = new Regex( "[^\\.]+\\.(\\w+)");

            Match tld_match = tld_regex.Match( domain_name );

            if ( tld_match.Success )
                return tld_match.Groups[1].Value;
            else
                throw new Exception( "Could not find TLD from domain!" );

        }

        private bool DoWhoisLookup(String strDomain, out String strResponse)
        {
            strResponse = "none";
            bool bSuccess = false;
            string tld = GetTLD(strDomain);
            string strServer = GetWhoisServer(GetTLD(strDomain));
            TcpClient tcpc = new TcpClient();
            try
            {
                tcpc.Connect(strServer, 43);
            }
            catch (SocketException ex)
            {
                System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "Could not connect to WHOIS server", System.Diagnostics.EventLogEntryType.Error);
                throw;
            }
            if ( tld.ToLower() == "com" || tld.ToLower() == "net" )
                strDomain = "=" + strDomain + "\r\n";
            else
                strDomain += "\r\n";
            Byte[] arrDomain = Encoding.ASCII.GetBytes(strDomain.ToCharArray());
            StringBuilder strBuilder = new StringBuilder();
            bSuccess = true;
            Stream s = tcpc.GetStream();
            s.Write(arrDomain, 0, strDomain.Length);

            StreamReader sr = new StreamReader(tcpc.GetStream(), Encoding.ASCII);
            string strLine = null;

            while (null != (strLine = sr.ReadLine()))
            {
                strBuilder.Append(strLine + "\n");
            }
            tcpc.Close();
            strResponse = strBuilder.ToString();
            if (strResponse.Length == 0)
            {
                throw new Exception("No whois data");
            }

            return bSuccess;
        }
    }


}
