package org.openidentity.oauth;
@FunctionalInterface public interface TargetResolver {
 String resolve(String resourceOrAudience) throws ProfileException;
}
