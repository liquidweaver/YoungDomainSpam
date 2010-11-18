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

    [Serializable()]
    public class SpammyWhoisException : System.Exception
    {
        public SpammyWhoisException() : base() { }
        public SpammyWhoisException(string message) : base(message) { }
        public SpammyWhoisException(string message, System.Exception inner) : base(message, inner) { }
        public SpammyWhoisException(string domain, string block_reason)
            : base(domain)
        {
            this.m_domain = domain;
            this.m_block_reason = block_reason;
        }


        // Constructor needed for serialization 
        // when exception propagates from a remoting server to the client. 
        protected SpammyWhoisException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) { }

        public string Domain
        {
            get { return m_domain; }
        }

        public string BlockReason
        {
            get { return m_block_reason; }
        }

        private string m_domain;
        private string m_block_reason;
    }

    [Serializable()]
    public class CannotWhoisCreationException : System.Exception
    {
        public CannotWhoisCreationException() : base() { }
        public CannotWhoisCreationException(string message) : base(message) { }
        public CannotWhoisCreationException(string message, System.Exception inner) : base(message, inner) { }
        public CannotWhoisCreationException(string domain, string whois_data)
            : base(domain)
        {
            this.m_domain = domain;
            this.m_whois_data = whois_data;
        }

        // Constructor needed for serialization 
        // when exception propagates from a remoting server to the client. 
        protected CannotWhoisCreationException(System.Runtime.Serialization.SerializationInfo info,
            System.Runtime.Serialization.StreamingContext context) { }

        public string Domain
        {
            get { return m_domain; }
        }

        public string WhoisData
        {
            get { return m_whois_data; }
        }

        private string m_domain;
        private string m_whois_data;
    }

    public class YoungDomainSpamAgent : SmtpReceiveAgent
    {
        const string url_regex = "http\\://([a-zA-Z0-9\\-\\.]+\\.)*([a-zA-Z0-9\\-]+\\.(?:[a-zA-Z]{2,4})|(?:co.uk))(/\\S*)?";
        const string real_whois_regex = "\\r?\\n.+whois\\s+server:\\s*([a-zA-Z0-9\\-\\.]+)";
        //const string creation_regex = "(?:(?:creat[^:]*:)|(?:created on))\\s*([\\w\\d\\-]+)";
        //const string creation_regex = "(?:(?:creat[^\\d]+)|(?:registration date[\\:\\s]+))([\\w\\d\\-]+)";
        //const string creation_regex = "(?:(?:creat[^\\d]+?(?!regist))|(?:registration date[\\:\\s]+))([a-zA-Z\\:\\d ]+)\\r?\\n";
        //const string creation_regex = "(?:(?:creation date\\:\\s*)|(?:created on\\:\\s*)|(?:registration date[\\:\\s]+)|(?:registered\\:[\\s]*))([a-zA-Z\\:\\d\\-  ]+?)\\r?\\n";
        const string creation_regex = "(?:(?:creation date\\:\\s*)|(?:created on\\.*?\\:\\s*)|(?:registration date[\\:\\s]+)|(?:registered\\:[\\s]*))([a-zA-Z\\:\\d\\-,  ]+?)\\.?\\r?\\n";
        const bool use_whois_servers_net = true;
        const string static_whois_server = "whois.arin.net";
        string[] alternative_time_formats = { "ddd MMM dd HH:mm:ss' gmt 'yyyy", "dd-MMM-yyyy HH:mm:ss' utc'" };
        string[] anonymous_triggers = { "whoisguard", "no match for", "not found:", "no records exist", "no domain (1)" };
        string[] known_good_domains = { "microsoft.com","w3c.org","w3.org","yahoo.com","gmail.com", "google.com","facebook.com","myspace.com","twitter.com","newegg.com", "metropark.com" };

        public string GetWhoisServer(string tld)
        {
            if ( use_whois_servers_net ) {
                return tld + ".whois-servers.net";
            }
            else
                return static_whois_server;
        }

        const string log_file_path = "C:\\metropark_agents\\";
        const string log_file = "yds.log";
        const int minimum_age = 200; //Age, in days, a domain must exist to no be considered 'young'
        Dictionary<string, bool> known_domains = new Dictionary<string, bool>();
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

            foreach ( string good_domain in known_good_domains ) {
                known_domains.Add(good_domain, false);
            }
        }

        private void OnEndOfDataHandler(
            ReceiveMessageEventSource source,
            EndOfDataEventArgs e)
        {
            string bodyAsText = "";
            StreamReader reader = new StreamReader(e.MailItem.Message.Body.GetContentReadStream(), Microsoft.Exchange.Data.Globalization.Charset.GetEncoding(e.MailItem.Message.Body.CharsetName), true);
            bodyAsText = reader.ReadToEnd();
            reader.Close();

            if ( this.ShouldBlockMessage(bodyAsText, e.MailItem.Message.Subject) ) {
                source.RejectMessage(
                    this.GetRejectResponse());
            }
        }

        private static void DebugLog(string what)
        {
            DebugLog(what, "", "");
        }

        private static void DebugLog(string what, string domain_name, string whois_data)
        {
            try {
                using ( StreamWriter SW = File.AppendText(log_file_path + log_file) ) {
                    SW.WriteLine(DateTime.Now.ToUniversalTime() + "\n---------------------------\n\t" + what + "\n\n");
                    SW.Close();
                }

                if ( domain_name != "" && whois_data != "" ) {
                    StreamWriter SW = File.CreateText(log_file_path + domain_name + ".badwhois");
                    SW.Write(whois_data);
                    SW.Close();
                }

            }
            catch ( Exception ex ) {
                System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "Could not write to log: " + log_file + "\n" + ex.Message, System.Diagnostics.EventLogEntryType.Error);
            }
        }

        private bool ShouldBlockMessage(string body, string subject)
        {
            // TODO: put logic here to decide whether to block 
            // the message.
            Regex rx = new Regex(url_regex);
            MatchCollection mc = rx.Matches(body);

            foreach ( Match submatch in mc ) {
                try {
                    string domain_name = submatch.Groups[2].ToString();
                    if ( known_domains.ContainsKey(domain_name) ) {
                        if ( known_domains[domain_name] == true ) {
                            cached_hits++;
                            throw new SpammyWhoisException(domain_name, "cached");
                        }
                        else
                            continue;
                    }

                    string whois_data = "";
                    DoWhoisLookup(domain_name, out whois_data);

                    //Annoymous == asshole
                    foreach ( string anon_string in anonymous_triggers ) {
                        if ( whois_data.Contains(anon_string) )
                            throw new SpammyWhoisException(domain_name, "anonymous - \"" + anon_string + "\"\n" + whois_data);
                    }

                    int age_in_days = GetAgeFromWhoisData(domain_name, whois_data);
                    if ( age_in_days < minimum_age )
                        throw new SpammyWhoisException(domain_name, "too young");
                }
                catch ( SpammyWhoisException e ) {
                    string domain_name = e.Domain;
                    known_domains[domain_name] = true;
                    blocked++;
                    if ( blocked % 100 == 0 ) {
                        System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", "Messages blocked so far: " + blocked + "\nErrors: " + whois_errors + "\nCached hits: " + cached_hits, System.Diagnostics.EventLogEntryType.Information);
                    }
                    DebugLog("Message blocked! Reason: " + e.BlockReason + " Subject:\"" + subject + "\" Domain: " + submatch.Groups[2].ToString());
                    return true;
                }
                catch ( CannotWhoisCreationException e ) {
                    whois_errors++;
                    string error_message = "Could not parse creation date from whois for domain " + e.Domain;
                    System.Diagnostics.EventLog.WriteEntry("YoungDomainSpamTransportAgent", error_message, System.Diagnostics.EventLogEntryType.Error);
                    DebugLog(error_message, e.Domain, e.WhoisData);
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

        private int GetAgeFromWhoisData(string domain, string whois_data)
        {
            Regex rx = new Regex(creation_regex);
            Match created_match = rx.Match(whois_data);
            if ( created_match.Success ) {
                DateTime created;
                if ( !DateTime.TryParse(created_match.Groups[1].ToString(), out created) )
                    if ( !DateTime.TryParseExact(created_match.Groups[1].ToString(),
                                                    alternative_time_formats,
                                                    new System.Globalization.CultureInfo("en-US"),
                                                    System.Globalization.DateTimeStyles.None,
                                                    out created) )
                        throw new CannotWhoisCreationException(domain, whois_data);

                TimeSpan age = DateTime.Now - created;

                return age.Days;
            }
            else
                throw new CannotWhoisCreationException(domain, whois_data);

            //Should be unreachable
            throw new Exception("Unreachable code");

        }

        private string GetTLD(string domain_name)
        {
            Regex tld_regex = new Regex("[^\\.]+\\.((?:co.uk)|(?:\\w+))");

            Match tld_match = tld_regex.Match(domain_name);

            if ( tld_match.Success )
                return tld_match.Groups[1].Value;
            else
                throw new Exception("Could not find TLD from domain!");

        }

        private void DoWhoisLookup(String strDomain, out String strResponse)
        {
            strResponse = "none";
            string tld = GetTLD(strDomain);
            string strServer = GetWhoisServer(GetTLD(strDomain));
            string strDomainToCheck = "";
            bool first_pass = true;
            while ( strServer != "" ) {
                TcpClient tcpc = new TcpClient();
                tcpc.Connect(strServer, 43);
                if ( first_pass && tld.ToLower() == "com" || tld.ToLower() == "net" )
                    strDomainToCheck = "=" + strDomain + "\r\n";
                else
                    strDomainToCheck = strDomain + "\r\n";
                first_pass = false;
                Byte[] arrDomain = Encoding.ASCII.GetBytes(strDomainToCheck.ToCharArray());
                StringBuilder strBuilder = new StringBuilder();
                Stream s = tcpc.GetStream();
                s.Write(arrDomain, 0, strDomainToCheck.Length);

                StreamReader sr = new StreamReader(tcpc.GetStream(), Encoding.ASCII);
                string strLine = null;

                while ( null != ( strLine = sr.ReadLine() ) ) {
                    strBuilder.Append(strLine + "\n");
                }
                tcpc.Close();
                strResponse = strBuilder.ToString().ToLower();

                if ( strResponse.Length == 0 ) {
                    throw new Exception("No whois data");
                }

                Regex match_real_whois = new Regex(Regex.Escape(strDomain) + real_whois_regex, RegexOptions.Singleline);
                Match real_whois = match_real_whois.Match(strResponse);

                if ( real_whois.Success ) {
                    strServer = real_whois.Groups[1].Value;
                }
                else
                    strServer = "";
            }
        }
    }


}
