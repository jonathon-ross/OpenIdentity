package org.openidentity.spring.ad;
import org.openidentity.ad.spnego.SpnegoAcceptor;
@FunctionalInterface
public interface SpnegoExchangeProvider {
 SpnegoAcceptor.Exchange begin();
}