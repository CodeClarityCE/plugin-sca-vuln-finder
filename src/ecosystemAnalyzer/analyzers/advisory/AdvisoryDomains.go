package advisory

// These domains have been selected through an analysis of the
// urls used in nvd reports for the relevant ecosystem

// Note that these URLS have been made mutually exclusive
// but the data intrinsitcly is not, thus play.google.com
// sometimes is for android related stuff but sometimes also for iphone related stuff
// which are two different "ecosystems", thus some false positives might be encountered

var COMMON_NODE_ADVISORY_ADVISORY_DOMAINS = []string{
	"nodejs.org",
	"nodejs.com",
	"nodesecurity.org",
	"nodesecurity.io",
	"npmjs.com",
	"npmjs.org",
	"yarnpkg.com",
	"blog.npmjs.org",
}

var COMMON_JAVASCRIPT_ADVISORY_DOMAINS = []string{
	"bugs.jquery.com",
	"bugs.jqueryui.com",
}

var COMMON_PHP_ADVISORY_DOMAINS = []string{
	"php.net",
	"php-security.org",
	"hardened-php.net",
	"phpbb.com",
	"phpgurukul.com",
	"phpmyfaq.de",
	"simplesamlphp.org",
	"php-fusion.co.uk",
	"phplist.com",
	"joomla.org",
	"joomlacode.org",
	"mybb.com",
	"phpbb.com",
	"craftercms.org",
	"simplesamlphp.org",
	"moodle.org",
	"wordpress.com",
	"wordpress.org",
	"typo3.org",
	"drupalcode.org",
	"drupal.org",
	"symfony.com",
	"wpscan.com",
	"wpvulndb.com",
	"wp-rocket.me",
	"extensions.joomla.org",
	"vel.joomla.org",
	"plugins.craftcms.com",
	"forge.typo3.org",
	"extensions.typo3.org",
	"plugins.trac.wordpress.org",
	"woocommerce.com",
	"wooengineering.wordpress.com",
	"wp-events-plugin.com",
	"cgit.drupalcode.org",
	"git.drupalcode.org",
}

var COMMON_PYTHON_ADVISORY_DOMAINS = []string{
	"python.org",
	"pypi.org",
	"djangoproject.com",
	"bugs.python.org",
}

var COMMON_RUBY_ADVISORY_DOMAINS = []string{
	"ruby-lang.org",
	"rubyonrails.org",
	"rubygems.org",
	"rubyforge.org",
	"bugs.ruby-lang.org",
	"ruby-doc.org",
	"rubysec.github.io",
	"rubysec.com",
	"discuss.rubyonrails.org",
}

var COMMON_RUST_ADVISORY_DOMAINS = []string{
	"rustsec.org",
	"rust-lang.org",
	"docs.rs",
	"crates.io",
}

var COMMON_JAVA_ADVISORY_DOMAINS = []string{
	"java.net",
	"android.com",
	"jenkins.io",
	"play.google.com",
}

var COMMON_NET_ADVISORY_DOMAINS = []string{
	"dotnetnuke.com",
}

var COMMON_SWIFT_ADVISORY_DOMAINS = []string{}

var COMMON_GO_ADVISORY_DOMAINS = []string{
	"golang.org",
}

var COMMON_PERL_ADVISORY_DOMAINS = []string{
	"perl.org",
	"metacpan.org",
	"rt.cpan.org",
	"cpansearch.perl.org",
	"blogs.perl.org",
}

var COMMON_C_OR_C_PLUS_PLUS_ADVISORY_DOMAINS = []string{}

var COMMON_NATIVE_OR_OS_ADVISORY_DOMAINS = []string{
	"debian.org",
	"lists.apache.org",
	"lists.fedoraproject.org",
	"lists.debian.org",
	"access.redhat.com",
	"h20564.www2.hp.com",
	"bugs.debian.org",
	"msrc.microsoft.com",
	"lists.apple.com",
	"h20565.www2.hp.com",
	"portal.msrc.microsoft.com",
	"h20566.www2.hpe.com",
	"vulnerability-lab.com",
	"tools.cisco.com",
	"www-01.ibm.com",
	"exchange.xforce.ibmcloud.com",
	"tibco.com",
	"security.gentoo.org",
	"rhn.redhat.com",
	"bugzilla.redhat.com",
	"h20000.www2.hp.com",
	"docs.microsoft.com",
	"oval.cisecurity.org",
	"us-cert.gov",
	"foxitsoftware.com",
	"bugs.chromium.org",
	"h20565.www2.hp.com",
	"kc.mcafee.com",
	"kb.pulsesecure.net",
	"ubuntu.com",
	"bugs.launchpad.net",
	"lists.opensuse.org",
	"helpx.adobe.com",
	"zerodayinitiative.com",
	"syss.de",
	"support.lenovo.com",
	"support.eset.com",
	"tools.cisco.com",
	"jira.opendaylight.org",
	"git.opendaylight.org",
	"ibm.com",
	"trac.webkit.org",
	"bugs.chromium.org",
	"pivotal.io",
	"marketplace.visualstudio.com",
	"ftp.gnome.org",
	"git.gnome.org",
	"bugzilla.gnome.org",
	"foxitsoftware.com",
	"puppet.com",
	"usn.ubuntu.com",
	"support.hpe.com",
	"cloudfoundry.org",
	"support.apple.com",
}
