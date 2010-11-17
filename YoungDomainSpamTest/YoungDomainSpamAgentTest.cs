using MetroparkAgents;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Exchange.Data.Transport;

namespace YoungDomainSpamTest
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
        ///A test for ShouldBlockMessage
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void ShouldBlockMessageTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value
            string body = "This is a Test Message.\nhttp://blarghle.google.cleuksputtoo.org  \n[NOTSPAM]";
            string subject = "Spammy message";
            bool expected = true; // TODO: Initialize to an appropriate value
            bool actual;
            actual = target.ShouldBlockMessage( body, subject );
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        ///A test for IsYoungDomain
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void IsYoungDomainTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value
            string domain_name = "cleuksputtoo.org"; // TODO: Initialize to an appropriate value
            bool expected = true; // TODO: Initialize to an appropriate value
            bool actual;
            actual = target.IsYoungDomain(domain_name);
            Assert.AreEqual(expected, actual);

            domain_name = "cnn.com";
            expected = false;
            actual = target.IsYoungDomain(domain_name);
            Assert.AreEqual(expected, actual);

            domain_name = "copperway.co.cc";
            expected = true;
            actual = target.IsYoungDomain(domain_name);
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        ///A test for DoWhoisLookup
        ///</summary>
        [TestMethod()]
        [DeploymentItem("YoungDomainSpam.dll")]
        public void DoWhoisLookupTest()
        {
            YoungDomainSpamAgent_Accessor target = new YoungDomainSpamAgent_Accessor(); // TODO: Initialize to an appropriate value
            string strDomain = "cleuksputtoo.org"; // TODO: Initialize to an appropriate value
            string strResponse = string.Empty; // TODO: Initialize to an appropriate value
            //string strResponseExpected = string.Empty; // TODO: Initialize to an appropriate value
            bool expected = true; // TODO: Initialize to an appropriate value
            bool actual;
            actual = target.DoWhoisLookup(strDomain, out strResponse);
            //Assert.AreEqual(strResponseExpected, strResponse);
            Assert.AreEqual(expected, actual);
        }
    }
}
