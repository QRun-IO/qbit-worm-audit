/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2025.  Kingsrook, LLC
 * 651 N Broad St Ste 205 # 6917 | Middletown DE 19709 | United States
 * contact@kingsrook.com
 * https://github.com/Kingsrook/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.wormaudit;


import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.kingsrook.qqq.backend.core.exceptions.QAuthenticationException;
import com.kingsrook.qqq.backend.core.model.metadata.QInstance;
import com.kingsrook.qqq.backend.core.model.session.QSession;
import com.kingsrook.qqq.backend.core.model.session.QSystemUserSession;
import com.kingsrook.qqq.backend.core.modules.authentication.QAuthenticationModuleInterface;


/*******************************************************************************
 ** Test authentication module that behaves like the token-based core modules
 ** (OAuth2, Auth0): a QSystemUserSession is always valid, a session it created
 ** is valid, and any other session has no token and fails validation with the
 ** same message the OAuth2 module produces (JWTDecodeException: The token is
 ** null).
 *******************************************************************************/
public class TokenRequiredAuthenticationModule implements QAuthenticationModuleInterface
{
   private static final Set<String> ISSUED = ConcurrentHashMap.newKeySet();



   /*******************************************************************************
    ** Issue a session that carries a token.
    *******************************************************************************/
   @Override
   public QSession createSession(QInstance qInstance, Map<String, String> context) throws QAuthenticationException
   {
      QSession session = new QSession();
      ISSUED.add(session.getUuid());
      return (session);
   }



   /*******************************************************************************
    ** Accept the system user and issued sessions; reject tokenless sessions.
    *******************************************************************************/
   @Override
   public boolean isSessionValid(QInstance instance, QSession session)
   {
      if(session instanceof QSystemUserSession || ISSUED.contains(session.getUuid()))
      {
         return (true);
      }
      throw (new IllegalStateException("The token is null"));
   }
}
