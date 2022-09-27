package hudson.markup;

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.CssSchema;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import com.google.common.collect.ImmutableSet;

import java.util.*;

public class BasicPolicy {
    public static final PolicyFactory POLICY_DEFINITION;

    static final Set<String> CUSTOM_PROPERTY_WHITELIST = ImmutableSet.of(
        "display"
    );

    @Restricted(NoExternalUse.class)
    public static final PolicyFactory ADDITIONS = new HtmlPolicyBuilder().allowElements("dl", "dt", "dd", "hr", "pre").toFactory();

    @Restricted(NoExternalUse.class)
    public static final PolicyFactory CUSTOM_STYLES = new HtmlPolicyBuilder().allowStyling( CssSchema.withProperties(CUSTOM_PROPERTY_WHITELIST)).toFactory();

    @Restricted(NoExternalUse.class)
    public static final PolicyFactory LINK_TARGETS = new HtmlPolicyBuilder()
            .allowElements("a")
            .requireRelsOnLinks("noopener", "noreferrer")
            .allowAttributes("target")
            .matching(false, "_blank")
            .onElements("a")
            .toFactory();

    @Restricted(NoExternalUse.class)
    public static final PolicyFactory CUSTOM_DETAILS = new HtmlPolicyBuilder()
            .allowElements("details", "summary")
            .allowAttributes("open")
            .onElements("details")
            .toFactory();

    static {
        POLICY_DEFINITION = 
                (Sanitizers.BLOCKS).
                and(Sanitizers.FORMATTING).
                and(Sanitizers.IMAGES).
                and(Sanitizers.LINKS).
                and(Sanitizers.STYLES).
                and(Sanitizers.TABLES).
                and(CUSTOM_STYLES).
                and(CUSTOM_DETAILS).
                and(ADDITIONS).
                and(LINK_TARGETS);
    }
}
