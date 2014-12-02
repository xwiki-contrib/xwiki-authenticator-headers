/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package com.xwiki.authentication.headers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.annotation.AllComponents;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.test.MockitoOldcoreRule;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.api.XWikiGroupService;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiServletRequest;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@AllComponents
public class XWikiHeadersAuthenticatorTest
{
    private static final String CONFIG_ID_FIELD = "xwiki.authentication.headers.id_field";
    private static final String CONFIG_AUTH_FIELD = "xwiki.authentication.headers.auth_field";
    private static final String CONFIG_SECRET_FIELD = "xwiki.authentication.headers.secret_field";
    private static final String CONFIG_SECRET_VALUE = "xwiki.authentication.headers.secret_value";
    private static final String CONFIG_GROUP_FIELD = "xwiki.authentication.headers.group_field";
    private static final String CONFIG_GROUP_VALUE_SEPARATOR = "xwiki.authentication.headers.group_value_separator";
    private static final String CONFIG_GROUPS_MAPPING = "xwiki.authentication.headers.groups_mapping";
    private static final String CONFIG_FIELDS_MAPPING = "xwiki.authentication.headers.fields_mapping";

    private static final String AUTH_FIELD = "remote_user";
    private static final String USERID_FIELD = "userid";
    private static final String GROUP_FIELD = "groups";
    private static final String FIELDS_MAPPING = "custom=custom_header,proprietary=proprietary_header";

    private static final String GROUPA_NAME = "GroupA";
    private static final String GROUPB_NAME = "GroupB";
    private static final String GROUPC_NAME = "GroupC";
    private static final String GROUPD_NAME = "GroupD";
    private static final String GROUPA_RID = "Group1";
    private static final String GROUPB_RID = "Group2";
    private static final String GROUPC_RID = "Group3";
    private static final String GROUPD_RID = "Group4";
    private static final String GROUPS_MAPPING = GROUPA_RID + '=' + GROUPA_NAME + ','
                                               + GROUPB_RID + '=' + GROUPB_NAME + ','
                                               + GROUPC_RID + '=' + GROUPC_NAME + ','
                                               + GROUPD_RID + '=' + GROUPD_NAME;

    private static final String USERNAME_SESSION_KEY = XWikiHeadersAuthenticator.class.getName() + ".username";

    private static final String USER_WIKI = "xwiki";
    private static final String USER_SPACE = "XWiki";

    private static final String SECRET_FIELD = "secret";

    private static final String TEST_USER = "test.user@example.com";
    private static final String VALID_TEST_USER = "test=user_example=com";
    private static final String TEST_USER_FN = USER_WIKI + ':' + USER_SPACE + '.' + VALID_TEST_USER;

    private static final String TEST2_USER = "test2";
    private static final String TEST2_USER_FN = USER_WIKI + ':' + USER_SPACE + '.' + TEST2_USER;

    @Rule
    public MockitoOldcoreRule oldcore = new MockitoOldcoreRule();

    private XWikiAuthService authenticator;

    private XWikiRequest request;

    private HttpServletRequest httpRequest;

    private HttpSession httpSession;

    private XWikiGroupService groupService;

    private Map<String, String> config = new HashMap<>();

    @Before
    public void before() throws Exception
    {
        //LoggerManager loggerManager = oldcore.getMocker().getInstance(LoggerManager.class);
        //loggerManager.setLoggerLevel(Logger.ROOT_LOGGER_NAME, LogLevel.DEBUG);

        authenticator = new XWikiHeadersAuthenticator();
        this.oldcore.getXWikiContext().setWikiId("wiki");

        when(this.oldcore.getMockXWiki().getAuthService()).thenReturn(authenticator);
        when(this.oldcore.getMockXWiki().Param(any(String.class), any(String.class))).then(
            new Answer<String>()
            {
                @Override
                public String answer(InvocationOnMock invocationOnMock) throws Throwable
                {
                    String paramName = (String) invocationOnMock.getArguments()[0];
                    String defaultValue = (String) invocationOnMock.getArguments()[1];

                    if (config.containsKey(paramName)) {
                        return config.get(paramName);
                    }
                    return defaultValue;
                }
            }
        );

        httpRequest = mock(HttpServletRequest.class);
        request = new XWikiServletRequest(httpRequest);
        httpSession = mock(HttpSession.class);
        when(httpSession.getId()).thenReturn("sessionId");
        when(httpRequest.getSession(any(Boolean.class))).thenReturn(httpSession);
        this.oldcore.getXWikiContext().setRequest(request);

        groupService = mock(XWikiGroupService.class);
        when(this.oldcore.getMockXWiki().getGroupService(any(XWikiContext.class))).thenReturn(groupService);

        when(groupService.getAllGroupsReferencesForMember(any(DocumentReference.class), eq(0), eq(0), any(XWikiContext.class))).then(
            new Answer<Collection<DocumentReference>>()
            {
                @Override
                public Collection<DocumentReference> answer(InvocationOnMock invocationOnMock) throws Throwable
                {
                    Collection<DocumentReference> result = new ArrayList<DocumentReference>();
                    DocumentReference userRef = (DocumentReference) invocationOnMock.getArguments()[0];
                    XWikiContext context = (XWikiContext) invocationOnMock.getArguments()[3];
                    BaseClass groupClass = context.getWiki().getGroupClass(context);
                    for(XWikiDocument doc : oldcore.getDocuments().values()) {
                        if (doc.getXObject(groupClass.getReference(), "member", USER_SPACE + '.' + userRef.getName()) != null) {
                            result.add(doc.getDocumentReference());
                        }
                    }
                    return result;
                }
            }
        );

        when(oldcore.getMockXWiki().createUser(any(String.class), any(Map.class), any(XWikiContext.class))).then(
            new Answer<Integer>()
            {
                @Override
                public Integer answer(InvocationOnMock invocationOnMock) throws Throwable
                {
                    String username = (String) invocationOnMock.getArguments()[0];
                    XWikiContext context = (XWikiContext) invocationOnMock.getArguments()[2];

                    if (saveNewUserGroupDocument(username, context) != null) {
                        return 1;
                    } else {
                        return -3;
                    }
                }
            }
        );

    }

    private XWikiDocument saveNewUserGroupDocument(String userGroup) throws Exception
    {
        return saveNewUserGroupDocument(userGroup, oldcore.getXWikiContext());
    }

    private XWikiDocument saveNewUserGroupDocument(String userGroup, XWikiContext context) throws Exception
    {
        XWikiDocument doc = oldcore.getMockXWiki().getDocument(new DocumentReference(USER_WIKI, USER_SPACE, userGroup),
            context);
        if (doc.isNew()) {
            oldcore.getMockXWiki().saveDocument(doc, "New document", oldcore.getXWikiContext());
            return doc;
        }
        return null;
    }

    @Test
    public void testFallbackWhenNoHeaderNoConfig() throws Exception
    {
        try {
            oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext());
        } catch (XWikiException e) {
            // Fallback to normal auth cause exception since the authenticator could not be initialized.
            assertThat(e.getModule(), equalTo(XWikiException.MODULE_XWIKI_USER));
            assertThat(e.getCode(), equalTo(XWikiException.ERROR_XWIKI_USER_INIT));
        }
    }

    @Test
    public void testWithoutConfigEmptySessionNewUser() throws Exception
    {
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(eq(VALID_TEST_USER), any(Map.class), any(XWikiContext.class));
        verify(httpSession, times(1)).setAttribute(USERNAME_SESSION_KEY, VALID_TEST_USER);
    }

   @Test
    public void testUserAlreadyInSession() throws Exception
    {
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        when(httpSession.getAttribute(USERNAME_SESSION_KEY)).thenReturn(VALID_TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), never())
            .createUser(any(String.class), any(Map.class), any(XWikiContext.class));
        verify(httpSession, never()).setAttribute(eq(USERNAME_SESSION_KEY), any(String.class));
    }

    @Test
    public void testWithoutConfigEmptySessionExistingUser() throws Exception
    {
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        saveNewUserGroupDocument(VALID_TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), never())
            .createUser(any(String.class), any(Map.class), any(XWikiContext.class));
        verify(httpSession, times(1)).setAttribute(USERNAME_SESSION_KEY, VALID_TEST_USER);
    }

    @Test
    public void testWithoutConfigEmptySessionNewUserTwice() throws Exception
    {
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(any(String.class), any(Map.class), any(XWikiContext.class));
    }

    @Test
    public void testFallbackWithWrongSecret() throws Exception
    {
        config.put(CONFIG_SECRET_FIELD, SECRET_FIELD);
        config.put(CONFIG_SECRET_VALUE, "password");
        when(httpRequest.getHeader(SECRET_FIELD)).thenReturn("badsecret");

        try {
            oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext());
        } catch (XWikiException e) {
            // Fallback to normal auth cause exception since the authenticator could not be initialized.
            assertThat(e.getModule(), equalTo(XWikiException.MODULE_XWIKI_USER));
            assertThat(e.getCode(), equalTo(XWikiException.ERROR_XWIKI_USER_INIT));
        }
    }

    @Test
    public void testWithRightSecret() throws Exception
    {
        config.put(CONFIG_SECRET_FIELD, SECRET_FIELD);
        config.put(CONFIG_SECRET_VALUE, "password");
        when(httpRequest.getHeader(SECRET_FIELD)).thenReturn("password");
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));
        verify(httpSession, times(1)).setAttribute(USERNAME_SESSION_KEY, VALID_TEST_USER);
    }

    @Test
    public void testUserWithMissingUserId() throws Exception
    {
        config.put(CONFIG_ID_FIELD, USERID_FIELD);
        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()), nullValue());
        verify(httpSession, never()).setAttribute(eq(USERNAME_SESSION_KEY), any(String.class));
    }

    @Test
    public void testNewUserDefaultFieldMapping() throws Exception
    {
        Map<String, String> extInfo = new HashMap<>();
        extInfo.put("email", "user@example.com");
        extInfo.put("first_name", "john");
        extInfo.put("last_name", "doe");
        extInfo.put("active", "1");

        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        when(httpRequest.getHeader("mail")).thenReturn(extInfo.get("email"));
        when(httpRequest.getHeader("givenname")).thenReturn(extInfo.get("first_name"));
        when(httpRequest.getHeader("sn")).thenReturn(extInfo.get("last_name"));

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(eq(VALID_TEST_USER), eq(extInfo), any(XWikiContext.class));
        verify(httpSession, times(1)).setAttribute(USERNAME_SESSION_KEY, VALID_TEST_USER);
    }

    @Test
    public void testNewUserCustomFieldMapping() throws Exception
    {
        Map<String, String> extInfo = new HashMap<>();
        extInfo.put("custom", "custom_value");
        extInfo.put("proprietary", "proprietary_value");
        extInfo.put("active", "1");

        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        when(httpRequest.getHeader("custom_header")).thenReturn(extInfo.get("custom"));
        when(httpRequest.getHeader("proprietary_header")).thenReturn(extInfo.get("proprietary"));

        config.put(CONFIG_FIELDS_MAPPING, FIELDS_MAPPING);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(eq(VALID_TEST_USER), eq(extInfo), any(XWikiContext.class));
        verify(httpSession, times(1)).setAttribute(USERNAME_SESSION_KEY, VALID_TEST_USER);
    }

    @Test
    public void testGroupMapping() throws Exception
    {
        final XWikiDocument groupAdoc = saveNewUserGroupDocument(GROUPA_NAME);
        final XWikiDocument groupBdoc = saveNewUserGroupDocument(GROUPB_NAME);
        final XWikiDocument groupCdoc = saveNewUserGroupDocument(GROUPC_NAME);
        final XWikiDocument groupDdoc = saveNewUserGroupDocument(GROUPD_NAME);

        config.put(CONFIG_GROUPS_MAPPING, GROUPS_MAPPING);
        config.put(CONFIG_GROUP_FIELD, GROUP_FIELD);

        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        when(httpRequest.getHeader(GROUP_FIELD)).thenReturn(GROUPC_RID + '|' + GROUPA_RID);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));


        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST2_USER);
        when(httpRequest.getHeader(GROUP_FIELD)).thenReturn(GROUPA_RID + '|' + GROUPD_RID + '|' + GROUPB_RID);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST2_USER_FN)));

        XWikiContext context = oldcore.getXWikiContext();
        String database = context.getWikiId();
        try {
            // Switch to main wiki to force users to be global users
            context.setWikiId(context.getMainXWiki());

            assertThat(groupService.getAllGroupsReferencesForMember(new DocumentReference(USER_WIKI, USER_SPACE, VALID_TEST_USER), 0, 0, context),
                containsInAnyOrder(new DocumentReference(USER_WIKI, USER_SPACE, GROUPA_NAME),
                                      new DocumentReference(USER_WIKI, USER_SPACE, GROUPC_NAME)));
            assertThat(groupService.getAllGroupsReferencesForMember(new DocumentReference(USER_WIKI, USER_SPACE, TEST2_USER), 0, 0, context),
                containsInAnyOrder(new DocumentReference(USER_WIKI, USER_SPACE, GROUPA_NAME),
                                      new DocumentReference(USER_WIKI, USER_SPACE, GROUPB_NAME),
                                      new DocumentReference(USER_WIKI, USER_SPACE, GROUPD_NAME)));
        } finally {
            context.setWikiId(database);
        }

        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST_USER);
        when(httpRequest.getHeader(GROUP_FIELD)).thenReturn(GROUPA_RID + '|' + GROUPD_RID + '|' + GROUPB_RID);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST_USER_FN)));

        when(httpRequest.getHeader(AUTH_FIELD)).thenReturn(TEST2_USER);
        when(httpRequest.getHeader(GROUP_FIELD)).thenReturn(GROUPC_RID + '|' + GROUPA_RID);

        assertThat(oldcore.getMockXWiki().getAuthService().checkAuth(oldcore.getXWikiContext()),
            equalTo(new XWikiUser(TEST2_USER_FN)));

        context = oldcore.getXWikiContext();
        database = context.getWikiId();
        try {
            // Switch to main wiki to force users to be global users
            context.setWikiId(context.getMainXWiki());

            assertThat(groupService.getAllGroupsReferencesForMember(new DocumentReference(USER_WIKI, USER_SPACE, VALID_TEST_USER), 0, 0, context),
                containsInAnyOrder(new DocumentReference(USER_WIKI, USER_SPACE, GROUPA_NAME),
                    new DocumentReference(USER_WIKI, USER_SPACE, GROUPB_NAME),
                    new DocumentReference(USER_WIKI, USER_SPACE, GROUPD_NAME)));
            assertThat(groupService.getAllGroupsReferencesForMember(new DocumentReference(USER_WIKI, USER_SPACE, TEST2_USER), 0, 0, context),
                containsInAnyOrder(new DocumentReference(USER_WIKI, USER_SPACE, GROUPA_NAME),
                    new DocumentReference(USER_WIKI, USER_SPACE, GROUPC_NAME)));
        } finally {
            context.setWikiId(database);
        }

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(eq(VALID_TEST_USER), any(Map.class), any(XWikiContext.class));

        verify(oldcore.getMockXWiki(), times(1))
            .createUser(eq(TEST2_USER), any(Map.class), any(XWikiContext.class));
    }
}
