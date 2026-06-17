package scanner

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type TechConfig struct {
	Timeout   time.Duration
	UserAgent string
}

func DetectTechnologies(ctx context.Context, targetURL string, cfg *TechConfig) *TechResult {
	if cfg == nil {
		cfg = &TechConfig{Timeout: 10 * time.Second, UserAgent: "SCANNER/1.0"}
	}
	result := &TechResult{}
	client := &http.Client{Timeout: cfg.Timeout}
	req, _ := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	req.Header.Set("User-Agent", cfg.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	html := string(bodyBytes)
	headers := resp.Header
	server := headers.Get("Server")

	if server != "" {
		result.Technologies = append(result.Technologies, TechInfo{
			Name: server, Category: "Web Server", Confidence: 100, Evidence: "Server: " + server,
		})
	}
	xpb := headers.Get("X-Powered-By")
	if xpb != "" {
		result.Technologies = append(result.Technologies, TechInfo{
			Name: xpb, Category: "Programming Language", Confidence: 90, Evidence: "X-Powered-By: " + xpb,
		})
	}
	via := headers.Get("Via")
	if via != "" {
		result.Technologies = append(result.Technologies, TechInfo{
			Name: via, Category: "Proxy", Confidence: 80, Evidence: "Via: " + via,
		})
	}
	xgen := headers.Get("X-Generator")
	if xgen != "" {
		result.Technologies = append(result.Technologies, TechInfo{
			Name: xgen, Category: "Generator", Confidence: 90, Evidence: "X-Generator: " + xgen,
		})
	}

	for _, c := range resp.Cookies() {
		cookiePatterns := map[string]string{
			"PHPSESSID":           "PHP",
			"JSESSIONID":          "Java Servlet",
			"ASP.NET_SessionId":   "ASP.NET",
			"ASPSESSIONID":        "ASP",
			"CFID":                "ColdFusion",
			"CFTOKEN":             "ColdFusion",
			"laravel_session":     "Laravel",
			"XSRF-TOKEN":          "Laravel",
			"symfony":             "Symfony",
			"drupal":              "Drupal",
			"wordpress_logged_in": "WordPress",
			"wp-settings":         "WordPress",
			"wordpress_test_cookie": "WordPress",
			"wp-postpass":         "WordPress",
			"wp_woocommerce_session": "WooCommerce",
			"cart_hash":           "WooCommerce",
			"shopify":             "Shopify",
			"_shopify_s":          "Shopify",
			"_shopify_y":          "Shopify",
			"_ga":                 "Google Analytics",
			"_gid":                "Google Analytics",
			"_fbp":                "Facebook Pixel",
			"_hjSession":          "Hotjar",
			"_hjAbsoluteSessionInProgress": "Hotjar",
			"intercom-id":         "Intercom",
			"intercom-session":    "Intercom",
			"__cfduid":            "Cloudflare",
			"incap_ses":           "Incapsula",
			"visid_incap":         "Incapsula",
			"akavpau":             "Akamai",
			"dtCookie":            "Dynatrace",
			"dtLatC":              "Dynatrace",
			"dtPC":                "Dynatrace",
			"dtSa":                "Dynatrace",
			"dtAdk":               "Dynatrace",
			"bm_sz":               "BotManager",
			"_abck":               "Akamai Bot",
			"ak_bmsc":             "Akamai Bot",
			"bm_mi":               "BotManager",
			"session-id":          "AWS ELB",
			"cluid":               "CloudLinux",
			"cpsession":           "cPanel",
			"cpanelf":             "cPanel",
			"plesk-panel":         "Plesk",
			"directadmin":         "DirectAdmin",
			"webamin":             "Webmin",
			"openid":              "OpenID",
			"wt3-":                "Webtrends",
			"nmstat":              "Siteimprove",
			"optimizely":          "Optimizely",
			"optimizelyEndUserId": "Optimizely",
			"mp_":                 "Mixpanel",
			"hubspotutk":          "HubSpot",
			"__hstc":              "HubSpot",
			"__hssc":              "HubSpot",
			"__hsfp":              "HubSpot",
		}
		for cookieName, tech := range cookiePatterns {
			if strings.Contains(c.Name, cookieName) || strings.EqualFold(c.Name, cookieName) {
				result.Technologies = append(result.Technologies, TechInfo{
					Name: tech, Category: "Cookie", Confidence: 95, Evidence: "Cookie: " + c.Name,
				})
			}
		}
	}

	patterns := []struct {
		Name     string
		Category string
		Pattern  string
	}{
		{"WordPress", "CMS", "wp-content|wp-includes|wp-json|wp-embed|wp-block|wp-emoji"},
		{"Joomla", "CMS", "joomla|com_content|com_modules|com_users|com_k2"},
		{"Drupal", "CMS", "drupal|Drupal.settings|drupalSettings"},
		{"Magento", "CMS", "mage/|Magento|var cookie|Mage.Cookies"},
		{"Shopify", "Ecommerce", "myshopify.com|Shopify|cdpn"},
		{"WooCommerce", "Ecommerce", "woocommerce|woo-variation|wc-"},
		{"Squarespace", "CMS", "squarespace|static.squarespace"},
		{"Wix", "CMS", "Wix|wix.com|wixstatic"},
		{"Blogger", "CMS", "blogger.com|blogspot"},
		{"Ghost", "CMS", "ghost|ghost.io|Ghost"},
		{"Concrete5", "CMS", "concrete5|ccm"},
		{"TYPO3", "CMS", "typo3|tx_"},
		{"Umbraco", "CMS", "umbraco|Umbraco"},
		{"Sitecore", "CMS", "sitecore|Sitecore"},
		{"Kentico", "CMS", "kentico|Kentico"},
		{"ExpressionEngine", "CMS", "expressionengine|ExpressionEngine"},
		{"Craft CMS", "CMS", "craft|Craft CMS"},
		{"October CMS", "CMS", "octobercms|October CMS"},
		{"Statamic", "CMS", "statamic|Statamic"},
		{"Kirby", "CMS", "kirby|Kirby CMS"},
		{"Grav", "CMS", "grav|Grav CMS"},
		{"PrestaShop", "Ecommerce", "prestashop|PrestaShop"},
		{"OpenCart", "Ecommerce", "opencart|OpenCart"},
		{"Zen Cart", "Ecommerce", "zen-cart|Zen Cart"},
		{"osCommerce", "Ecommerce", "oscommerce|osC"},
		{"nopCommerce", "Ecommerce", "nopcommerce|NopCommerce"},
		{"BigCommerce", "Ecommerce", "bigcommerce|BigCommerce"},
		{"LemonStand", "Ecommerce", "lemonstand|LemonStand"},
		{"3dcart", "Ecommerce", "3dcart|3dCart"},
		{"Volusion", "Ecommerce", "volusion|Volusion"},
		{"CS-Cart", "Ecommerce", "cscart|CS-Cart"},

		{"Laravel", "Framework", "laravel|Laravel|CSRF-Token|csrf-token"},
		{"Symfony", "Framework", "symfony|Symfony|sf-"},
		{"Django", "Framework", "django|Django|csrfmiddlewaretoken|django-admin"},
		{"Ruby on Rails", "Framework", "rails|Rails|csrf-token|actionpack"},
		{"Express", "Framework", "express|Express|x-powered-by: express"},
		{"Spring Boot", "Framework", "spring|Spring|spring-boot|springboot"},
		{"Flask", "Framework", "flask|Flask|jinja|Jinja2"},
		{"ASP.NET MVC", "Framework", "aspnetmvc|ASP.NET MVC|__VIEWSTATE"},
		{"ASP.NET Core", "Framework", "aspnetcore|ASP.NET Core|__VIEWSTATE"},
		{"CakePHP", "Framework", "cakephp|CakePHP|CAKEPHP"},
		{"CodeIgniter", "Framework", "codeigniter|CodeIgniter|ci_session"},
		{"Yii", "Framework", "yii|Yii|yiisoft|yii2"},
		{"Zend Framework", "Framework", "zend|Zend Framework|zf-"},
		{"Phalcon", "Framework", "phalcon|Phalcon"},
		{"Slim", "Framework", "slim|Slim Framework"},
		{"FuelPHP", "Framework", "fuelphp|FuelPHP"},
		{"Fat-Free", "Framework", "fat-free|Fat-Free"},
		{"Kohana", "Framework", "kohana|Kohana"},
		{"Grails", "Framework", "grails|Grails"},
		{"Play Framework", "Framework", "play|Play framework"},
		{"Mojave", "Framework", "mojave|Mojave"},
		{"Phoenix", "Framework", "phoenix|Phoenix Framework"},
		{"Elixir", "Framework", "elixir|Elixir"},

		{"React", "JavaScript Library", "react|React|reactjs|create-react-app|__react"},
		{"Vue.js", "JavaScript Library", "vue|Vue|vuejs|__vue__|vue-router"},
		{"Angular", "JavaScript Library", "angular|Angular|ng-|angularjs|angular2"},
		{"Svelte", "JavaScript Library", "svelte|Svelte|__svelte"},
		{"jQuery", "JavaScript Library", "jquery|jQuery|jquery-"},
		{"Preact", "JavaScript Library", "preact|Preact"},
		{"Ember.js", "JavaScript Library", "ember|Ember|emberjs"},
		{"Backbone.js", "JavaScript Library", "backbone|Backbone"},
		{"Knockout.js", "JavaScript Library", "knockout|Ko|ko."},
		{"Alpine.js", "JavaScript Library", "alpinejs|AlpineJS|x-data"},
		{"Stimulus", "JavaScript Library", "stimulus|Stimulus|stimulusjs"},
		{"Hotwire", "JavaScript Library", "hotwire|Hotwire|turbo|turbolinks"},
		{"HTMX", "JavaScript Library", "htmx|HTMX|hx-"},
		{"Unpoly", "JavaScript Library", "unpoly|unpolyjs"},
		{"MooTools", "JavaScript Library", "mootools|MooTools"},
		{"Prototype", "JavaScript Library", "prototype|Prototype.js"},
		{"Dojo", "JavaScript Library", "dojo|Dojo Toolkit"},
		{"Ext JS", "JavaScript Library", "extjs|Ext JS"},
		{"Mithril", "JavaScript Library", "mithril|Mithril"},
		{"Marko", "JavaScript Library", "marko|MarkoJS"},
		{"Riot.js", "JavaScript Library", "riot|Riot.js"},
		{"Petite-Vue", "JavaScript Library", "petite-vue"},

		{"Next.js", "JavaScript Framework", "__NEXT_DATA|nextjs|next.js|_next"},
		{"Nuxt.js", "JavaScript Framework", "__NUXT__|nuxt|nuxtjs"},
		{"Remix", "JavaScript Framework", "remix|Remix|@remix"},
		{"SvelteKit", "JavaScript Framework", "sveltekit|SvelteKit"},
		{"SolidStart", "JavaScript Framework", "solidstart|SolidStart"},
		{"Astro", "JavaScript Framework", "astro|Astro"},
		{"Gatsby", "JavaScript Framework", "gatsby|Gatsby|___gatsby"},
		{"Hugo", "Static Site Generator", "hugo|Hugo"},
		{"Jekyll", "Static Site Generator", "jekyll|Jekyll"},
		{"Eleventy", "Static Site Generator", "eleventy|11ty"},
		{"Hexo", "Static Site Generator", "hexo|Hexo"},
		{"Docusaurus", "Static Site Generator", "docusaurus|Docusaurus"},
		{"VitePress", "Static Site Generator", "vitepress|VitePress"},
		{"MkDocs", "Static Site Generator", "mkdocs|MkDocs"},
		{"GitBook", "Static Site Generator", "gitbook|GitBook"},

		{"Bootstrap", "CSS Framework", "bootstrap|Bootstrap|bootstrap-"},
		{"Tailwind CSS", "CSS Framework", "tailwind|Tailwind|tw-"},
		{"Foundation", "CSS Framework", "foundation|Foundation|zurb"},
		{"Bulma", "CSS Framework", "bulma|Bulma"},
		{"Materialize", "CSS Framework", "materialize|Materialize"},
		{"Material UI", "CSS Framework", "@mui|MUI|material-ui"},
		{"Chakra UI", "CSS Framework", "@chakra|chakra-ui"},
		{"Ant Design", "CSS Framework", "antd|ant-design|ant-"},
		{"PrimeFaces", "CSS Framework", "primefaces|PrimeFaces|primeui"},
		{"Semantic UI", "CSS Framework", "semantic|Semantic-UI"},
		{"UIKit", "CSS Framework", "uikit|UIkit"},
		{"PureCSS", "CSS Framework", "purecss|Pure"},
		{"Spectre CSS", "CSS Framework", "spectre|Spectre.css"},
		{"Milligram", "CSS Framework", "milligram|Milligram"},
		{"Tachyons", "CSS Framework", "tachyons|Tachyons"},

		{"Font Awesome", "Icon Font", "font-awesome|Font-Awesome|fa-|fa "},
		{"Material Icons", "Icon Font", "material-icons|Material+Icons"},
		{"Ionicons", "Icon Font", "ionicons|ion-"},
		{"Glyphicons", "Icon Font", "glyphicons|Glyphicons"},
		{"Feather Icons", "Icon Font", "feather|feather-icons"},
		{"Boxicons", "Icon Font", "boxicons|bx-|bxs-|bxl-"},
		{"Phosphor Icons", "Icon Font", "phosphor|ph-"},
		{"Heroicons", "Icon Font", "heroicons|hero-"},		
		{"Lucide", "Icon Font", "lucide|lucide-react|lucide-vue"},

		{"Google Analytics", "Analytics", "google-analytics|ga.js|gtag|gtag.js|analytics.js"},
		{"Google Tag Manager", "Analytics", "googletagmanager|GTM-"},
		{"Facebook Pixel", "Analytics", "facebook-pixel|fbq|connect.facebook"},
		{"Hotjar", "Analytics", "hotjar|Hotjar|static.hotjar"},
		{"Mixpanel", "Analytics", "mixpanel|Mixpanel|cdn.mxpnl"},
		{"Amplitude", "Analytics", "amplitude|Amplitude"},
		{"Segment", "Analytics", "segment|Segment|cdn.segment"},
		{"Heap", "Analytics", "heap|Heap|heapanalytics"},
		{"FullStory", "Analytics", "fullstory|FullStory|rs.fullstory"},
		{"CrazyEgg", "Analytics", "crazyegg|CrazyEgg"},
		{"Clicky", "Analytics", "clicky|Clicky|static.clicky"},
		{"Matomo", "Analytics", "matomo|Matomo|piwik"},
		{"Plausible", "Analytics", "plausible|Plausible|plausible.io"},
		{"Fathom", "Analytics", "fathom|Fathom Analytics"},
		{"Umami", "Analytics", "umami|Umami Analytics"},
		{"Honeycomb", "Analytics", "honeycomb|Honeycomb"},

		{"Cloudflare", "CDN", "cloudflare|CloudFlare|cloudflare-nginx"},
		{"Cloudfront", "CDN", "cloudfront.net|cloudfront"},
		{"Fastly", "CDN", "fastly|Fastly|fastly-"},
		{"Akamai", "CDN", "akamai|Akamai|akamaihd"},
		{"Incapsula", "CDN", "incapsula|Incapsula"},
		{"Sucuri", "CDN", "sucuri|Sucuri|cloudproxy"},
		{"StackPath", "CDN", "stackpath|StackPath"},
		{"KeyCDN", "CDN", "keycdn|KeyCDN"},
		{"BunnyCDN", "CDN", "bunnycdn|BunnyCDN|bunny.net"},
		{"Azure CDN", "CDN", "azureedge|azurefd"},
		{"G Core Labs", "CDN", "gcdn|gcore"},
		{"Vercel", "CDN", "vercel|Vercel"},
		{"Netlify", "CDN", "netlify|Netlify"},
		{"Heroku", "PaaS", "heroku|Heroku|herokuapp"},
		{"GitHub Pages", "PaaS", "github.io|github pages"},
		{"GitLab Pages", "PaaS", "gitlab.io"},
		{"Fly.io", "PaaS", "fly.io|Fly"},
		{"Railway", "PaaS", "railway|Railway"},

		{"Nginx", "Web Server", "nginx|nginx/"},
		{"Apache HTTP Server", "Web Server", "apache|Apache|httpd"},
		{"IIS", "Web Server", "iis|IIS|Microsoft-IIS"},
		{"OpenResty", "Web Server", "openresty|OpenResty"},
		{"Caddy", "Web Server", "caddy|Caddy"},
		{"Lighttpd", "Web Server", "lighttpd|Lighttpd"},
		{"LiteSpeed", "Web Server", "litespeed|LiteSpeed|LiteSpeed"},
		{"Tomcat", "Web Server", "tomcat|Tomcat|Apache Tomcat"},
		{"JBoss", "Web Server", "jboss|JBoss|WildFly"},
		{"Jetty", "Web Server", "jetty|Jetty|eclipse jetty"},
		{"WebLogic", "Web Server", "weblogic|WebLogic"},
		{"WebSphere", "Web Server", "websphere|WebSphere"},
		{"Kestrel", "Web Server", "kestrel|Kestrel"},
		{"Google Frontend", "Web Server", "gfe|GFE|google-frontend"},
		{"Node.js", "Web Server", "node.js|Node.js|nodejs"},

		{"PHP", "Language", "php|PHP|x-powered-by: php"},
		{"Java", "Language", "java|Java|x-powered-by: java"},
		{"Python", "Language", "python|Python|x-powered-by: python"},
		{"Ruby", "Language", "ruby|Ruby|x-powered-by: ruby"},
		{"Go", "Language", "go|Go|x-powered-by: go"},
		{"Rust", "Language", "rust|Rust|x-powered-by: rust"},
		{"C#", "Language", "csharp|C#|x-powered-by: csharp"},
		{"Scala", "Language", "scala|Scala|x-powered-by: scala"},
		{"Kotlin", "Language", "kotlin|Kotlin|x-powered-by: kotlin"},
		{"Perl", "Language", "perl|Perl|x-powered-by: perl"},
		{"Haskell", "Language", "haskell|Haskell|x-powered-by: haskell"},
		{"Clojure", "Language", "clojure|Clojure|x-powered-by: clojure"},
		{"Dart", "Language", "dart|Dart|x-powered-by: dart"},

		{"MySQL", "Database", "mysql|MySQL"},
		{"PostgreSQL", "Database", "postgresql|PostgreSQL|postgres"},
		{"MongoDB", "Database", "mongodb|MongoDB|mongo"},
		{"Redis", "Database", "redis|Redis"},
		{"SQLite", "Database", "sqlite|SQLite"},
		{"MariaDB", "Database", "mariadb|MariaDB"},
		{"Oracle DB", "Database", "oracle|Oracle DB"},
		{"SQL Server", "Database", "mssql|sqlserver|SQL Server"},
		{"Elasticsearch", "Database", "elasticsearch|Elasticsearch"},
		{"CouchDB", "Database", "couchdb|CouchDB"},
		{"Firebase", "Database", "firebase|Firebase|firebaseio"},
		{"Supabase", "Database", "supabase|Supabase"},
		{"PlanetScale", "Database", "planetscale|PlanetScale"},
		{"Neon", "Database", "neon|Neon.tech"},

		{"Grafana", "Monitoring", "grafana|Grafana|grafana-"},
		{"Prometheus", "Monitoring", "prometheus|Prometheus"},
		{"Datadog", "Monitoring", "datadog|Datadog"},
		{"New Relic", "Monitoring", "newrelic|New Relic|newrelic-"},
		{"Dynatrace", "Monitoring", "dynatrace|Dynatrace|dtjs"},
		{"Sentry", "Monitoring", "sentry|Sentry|sentry.io"},
		{"Splunk", "Monitoring", "splunk|Splunk"},
		{"Elastic APM", "Monitoring", "elastic-apm|elasticapm"},
		{"AppDynamics", "Monitoring", "appdynamics|AppDynamics"},
		{"Instana", "Monitoring", "instana|Instana"},

		{"Auth0", "Auth", "auth0|Auth0"},
		{"Okta", "Auth", "okta|Okta|oktass"},
		{"Keycloak", "Auth", "keycloak|Keycloak"},
		{"Firebase Auth", "Auth", "firebase-auth|firebaseui"},
		{"Clerk", "Auth", "clerk|Clerk"},
		{"Supabase Auth", "Auth", "supabase-auth"},
		{"Amazon Cognito", "Auth", "cognito|Cognito|cognito-identity"},
		{"Azure AD", "Auth", "azuread|AzureAD|login.microsoftonline"},
		{"Google Identity", "Auth", "google-signin|google-signin2|gsi"},
		{"Facebook Login", "Auth", "facebook-login|fb-login"},
		{"GitHub Login", "Auth", "github-login|github-oauth"},

		{"Cloudflare Bot Management", "Security", "cf-bm|cloudflare-bot"},
		{"reCAPTCHA", "Security", "recaptcha|reCAPTCHA|google.com/recaptcha"},
		{"hCaptcha", "Security", "hcaptcha|hCaptcha"},
		{"Akismet", "Security", "akismet|Akismet"},
		{"ModSecurity", "Security", "modsecurity|ModSecurity"},
		{"Naxsi", "Security", "naxsi|Naxsi"},
		{"Fail2Ban", "Security", "fail2ban|Fail2ban"},
		{"Ratelimit", "Security", "ratelimit|RateLimit|x-ratelimit"},

		{"Magento", "Ecommerce", "mage/|Magento|var cookie|Mage.Cookies"},
		{"WooCommerce", "Ecommerce", "woocommerce|woo-variation|wc-"},
		{"Shopify", "Ecommerce", "shopify|Shopify|myshopify.com"},
		{"BigCommerce", "Ecommerce", "bigcommerce|BigCommerce"},
		{"Salesforce Commerce Cloud", "Ecommerce", "demandware|Salesforce Commerce"},
		{"Hybris", "Ecommerce", "hybris|SAP Hybris"},
		{"Commercetools", "Ecommerce", "commercetools|Commercetools"},
		{"Medusa", "Ecommerce", "medusa|Medusa.js"},
		{"Saleor", "Ecommerce", "saleor|Saleor"},
		{"Vendure", "Ecommerce", "vendure|Vendure"},
		{"Sylius", "Ecommerce", "sylius|Sylius"},
		{"Spree", "Ecommerce", "spree|Spree Commerce"},

		{"Strapi", "Headless CMS", "strapi|Strapi"},
		{"Contentful", "Headless CMS", "contentful|Contentful"},
		{"Sanity", "Headless CMS", "sanity|Sanity"},
		{"Prismic", "Headless CMS", "prismic|Prismic"},
		{"Storyblok", "Headless CMS", "storyblok|Storyblok"},
		{"Kentico Kontent", "Headless CMS", "kenticocloud|Kentico Kontent"},
		{"Cosmic CMS", "Headless CMS", "cosmicjs|Cosmic"},
		{"Butter CMS", "Headless CMS", "buttercms|Butter CMS"},
		{"Hygraph", "Headless CMS", "hygraph|Hygraph|graphcms"},
		{"Directus", "Headless CMS", "directus|Directus"},
		{"Payload CMS", "Headless CMS", "payloadcms|Payload CMS"},
		{"Webiny", "Headless CMS", "webiny|Webiny"},
		{"TinaCMS", "Headless CMS", "tinacms|TinaCMS"},

		{"Jenkins", "CI/CD", "jenkins|Jenkins|x-jenkins"},
		{"GitLab CI", "CI/CD", "gitlab-ci|GitLab CI"},
		{"GitHub Actions", "CI/CD", "github-actions|GitHub Actions"},
		{"CircleCI", "CI/CD", "circleci|CircleCI"},
		{"Travis CI", "CI/CD", "travis-ci|Travis CI"},
		{"TeamCity", "CI/CD", "teamcity|TeamCity"},
		{"Bamboo", "CI/CD", "bamboo|Bamboo"},
		{"Drone", "CI/CD", "drone|Drone CI"},
		{"ArgoCD", "CI/CD", "argocd|ArgoCD"},
		{"Flux", "CI/CD", "flux|Flux CD"},

		{"Algolia", "Search", "algolia|Algolia"},
		{"Elasticsearch", "Search", "elasticsearch|Elasticsearch"},
		{"Meilisearch", "Search", "meilisearch|MeiliSearch"},
		{"Typesense", "Search", "typesense|Typesense"},
		{"Swiftype", "Search", "swiftype|Swiftype"},
		{"Search.io", "Search", "search.io|Sajari"},
		{"Solr", "Search", "solr|Apache Solr"},
		{"Sphinx", "Search", "sphinx|Sphinx search"},

		{"Google Maps", "Maps", "maps.google|google-maps|maps.googleapis"},
		{"Mapbox", "Maps", "mapbox|Mapbox"},
		{"Leaflet", "Maps", "leaflet|Leaflet|leaflet.js"},
		{"OpenStreetMap", "Maps", "openstreetmap|OSM|tile.openstreetmap"},
		{"Azure Maps", "Maps", "azure-maps|Azure Maps"},
		{"MapKit", "Maps", "mapkit|MapKit JS"},

		{"Stripe", "Payment", "stripe|Stripe|stripe.com|stripe-"},
		{"PayPal", "Payment", "paypal|PayPal|paypal.com"},
		{"Square", "Payment", "square|Square|squareup"},
		{"Braintree", "Payment", "braintree|Braintree"},
		{"Adyen", "Payment", "adyen|Adyen"},
		{"Shopify Payments", "Payment", "shopify-payments"},
		{"Mollie", "Payment", "mollie|Mollie"},
		{"Paddle", "Payment", "paddle|Paddle"},
		{"Lemon Squeezy", "Payment", "lemonsqueezy|Lemon Squeezy"},
		{"Gumroad", "Payment", "gumroad|Gumroad"},
		{"Recurly", "Payment", "recurly|Recurly"},
		{"Chargebee", "Payment", "chargebee|Chargebee"},
		{"Plaid", "Payment", "plaid|Plaid"},

		{"Intercom", "Chat", "intercom|Intercom"},
		{"Drift", "Chat", "drift|Drift"},
		{"Crisp", "Chat", "crisp|Crisp"},
		{"Zendesk", "Chat", "zendesk|Zendesk"},
		{"Freshdesk", "Chat", "freshdesk|Freshdesk"},
		{"Help Scout", "Chat", "helpscout|Help Scout"},
		{"Tidio", "Chat", "tidio|Tidio"},
		{"LiveChat", "Chat", "livechat|LiveChat"},
		{"Olark", "Chat", "olark|Olark"},
		{"SnapEngage", "Chat", "snapengage|SnapEngage"},
		{"Tawk.to", "Chat", "tawk|Tawk.to"},
		{"Messenger", "Chat", "messenger|facebook-messenger"},
		{"WhatsApp Widget", "Chat", "whatsapp|wa.me"},
		{"Telegram Widget", "Chat", "telegram|t.me"},

		{"Google Fonts", "Fonts", "fonts.googleapis|fonts.gstatic"},
		{"Adobe Fonts", "Fonts", "fonts.adobe|typekit|use.typekit"},
		{"FontShare", "Fonts", "fontshare|Fontshare"},
	}

	for _, p := range patterns {
		re := regexp.MustCompile(`(?i)` + p.Pattern)
		isMatch := re.MatchString(html) || re.MatchString(server)
		if !isMatch {
			for _, hv := range headers {
				for _, h := range hv {
					if re.MatchString(h) {
						isMatch = true
						break
					}
				}
				if isMatch {
					break
				}
			}
		}
		if isMatch {
			found := false
			for _, t := range result.Technologies {
				if t.Name == p.Name {
					found = true
					break
				}
			}
			if !found {
				result.Technologies = append(result.Technologies, TechInfo{
					Name: p.Name, Category: p.Category, Confidence: 80, Evidence: "Pattern: " + p.Pattern,
				})
			}
		}
	}

	genRe := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']([^"']+)["']`)
	if matches := genRe.FindStringSubmatch(html); len(matches) > 1 {
		result.Technologies = append(result.Technologies, TechInfo{
			Name: matches[1], Category: "Generator", Confidence: 100, Evidence: "Meta generator: " + matches[1],
		})
	}

	scriptRe := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	for _, match := range scriptRe.FindAllStringSubmatch(html, -1) {
		src := match[1]
		checks := []struct {
			pattern string
			name    string
			version string
		}{
			{`jquery-([0-9.]+)`, "jQuery", "$1"},
			{`bootstrap-([0-9.]+)`, "Bootstrap", "$1"},
			{`react(-[0-9.]+)?`, "React", "$1"},
			{`vue-([0-9.]+)`, "Vue.js", "$1"},
			{`angular-([0-9.]+)`, "Angular", "$1"},
			{`moment-([0-9.]+)`, "Moment.js", "$1"},
			{`lodash-([0-9.]+)`, "Lodash", "$1"},
			{`underscore-([0-9.]+)`, "Underscore.js", "$1"},
			{`d3.v?([0-9.]+)`, "D3.js", "$1"},
			{`chart-([0-9.]+)`, "Chart.js", "$1"},
			{`axios-([0-9.]+)`, "Axios", "$1"},
		}
		for _, check := range checks {
			re := regexp.MustCompile(check.pattern)
			if m := re.FindStringSubmatch(src); len(m) > 1 {
				result.Technologies = append(result.Technologies, TechInfo{
					Name: check.name, Category: "JavaScript Library", Version: m[1], Confidence: 90, Evidence: "Script: " + src,
				})
			}
		}
	}

	return result
}
