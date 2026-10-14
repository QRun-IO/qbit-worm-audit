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

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.DockerClientFactory;

/*******************************************************************************
 ** Tests and fixtures for requires docker condition.
 *******************************************************************************/
public class RequiresDockerCondition implements ExecutionCondition
{
   /*******************************************************************************
    ** Verify evaluate execution condition.
    *******************************************************************************/
   @Override
   public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context)
   {
      boolean available;
      try
      {
         available = DockerClientFactory.instance().isDockerAvailable();
      }
      catch(Exception | LinkageError e)
      {
         available = false;
      }
      return (evaluate(available, System.getenv("CI")));
   }

   /*******************************************************************************
    ** Verify evaluate.
    *******************************************************************************/
   static ConditionEvaluationResult evaluate(boolean available, String ci)
   {
      if(available)
      {
         return (ConditionEvaluationResult.enabled("Docker is available"));
      }
      if(ci != null)
      {
         throw new IllegalStateException("Docker is required when CI is set");
      }
      return (ConditionEvaluationResult.disabled(
            "Docker unavailable; coordinator must run PostgreSQL acceptance tests"));
   }
}
