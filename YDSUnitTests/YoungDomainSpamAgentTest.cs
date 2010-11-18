using MetroparkAgents;
using Microsoft.VisualStudio.TestTools.UnitTesting;
namespace YDSUnitTests
{
    
    
    /// <summary>
    ///This is a test class for YoungDomainSpamAgentTest and is intended
    ///to contain all YoungDomainSpamAgentTest Unit Tests
    ///</summary>
    [TestClass()]
    public class YoungDomainSpamAgentTest
    {


        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        /// <summary>
        ///A test for GetWhoisServer
        ///</summary>
        [TestMethod()]
        public void GetWhoisServerTest()
        {
            YoungDomainSpamAgent target = new YoungDomainSpamAgent(); // TODO: Initialize to an appropriate value
            string tld = "com"; // TODO: Initialize to an appropriate value
            string actual = string.Empty;
            actual = target.GetWhoisServer(tld);
            Assert.AreNotEqual(actual, string.Empty);
        }

        /// <summary>
        ///A test for GetTLD
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void GetTLDTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value
            string domain_name = "copperstone.co.uk"; // TODO: Initialize to an appropriate value
            string expected = "co.uk"; // TODO: Initialize to an appropriate value
            string actual;
            actual = target.GetTLD(domain_name);
            Assert.AreEqual(expected, actual);

            domain_name = "metropark.com"; // TODO: Initialize to an appropriate value
            expected = "com"; // TODO: Initialize to an appropriate value
            actual = "";
            actual = target.GetTLD(domain_name);
            Assert.AreEqual(expected, actual);

        }

        /// <summary>
        ///A test for GetAgeFromWhoisData
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void GetAgeFromWhoisDataTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value

            System.IO.DirectoryInfo di = new System.IO.DirectoryInfo("../../../whois_samples");
            System.IO.FileInfo[] rgFiles = di.GetFiles("*.whois");
            if ( rgFiles.Length == 0 )
                Assert.Inconclusive("No test files for whois creation matching.");
            else {
                foreach ( System.IO.FileInfo fi in rgFiles ) {
                    string whois_data = System.IO.File.ReadAllText(fi.FullName).ToLower(); //Need lowercase
                    int age = target.GetAgeFromWhoisData(fi.Name, whois_data);
                    System.Diagnostics.Debug.WriteLine("Domain File: " + fi.Name + ", age: " + age);
                }
            }
            System.Diagnostics.Debug.WriteLine(" Age tests complete.");
        }

        /// <summary>
        ///A test for DoWhoisLookup
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void DoWhoisLookupTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value
            string strDomain = "twitter.com"; // TODO: Initialize to an appropriate value
            string strResponse = string.Empty; // TODO: Initialize to an appropriate value
            target.DoWhoisLookup(strDomain, out strResponse);
            Assert.AreNotEqual(string.Empty, strResponse);
        }
    }
}
