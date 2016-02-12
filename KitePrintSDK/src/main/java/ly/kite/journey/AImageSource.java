/*****************************************************
 *
 * AImageSource.java
 *
 *
 * Modified MIT License
 *
 * Copyright (c) 2010-2015 Kite Tech Ltd. https://www.kite.ly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The software MAY ONLY be used with the Kite Tech Ltd platform and MAY NOT be modified
 * to be used with any competitor platforms. This means the software MAY NOT be modified 
 * to place orders with any competitors to Kite Tech Ltd, all orders MUST go through the
 * Kite Tech Ltd platform servers. 
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *****************************************************/

///// Package Declaration /////

package ly.kite.journey;


///// Import(s) /////

import java.util.List;

import android.app.Activity;
import android.app.Fragment;
import android.content.Context;
import android.content.Intent;
import android.view.Menu;

import ly.kite.catalogue.Asset;


///// Class Declaration /////

/*****************************************************
 *
 * An image source.
 *
 *****************************************************/
abstract public class AImageSource
  {
  ///// Static Constant(s) /////

  static private final String  LOG_TAG                = "AImageSource";

  static public  final int     UNLIMITED_NO_OF_IMAGES = 0;


  ///// Member Variable(s) /////

  private int  mBackgroundColourResourceId;
  private int  mIconResourceId;
  private int  mLabelResourceId;

  private int  mMenuItemId;
  private int  mMenuItemTitleResourceId;

  private int  mActivityRequestCode;


  ///// Static Method(s) /////


  ///// Constructor(s) /////

  protected AImageSource( int backgroundColourResourceId,
                          int iconResourceId,
                          int labelResourceId,
                          int menuItemId,
                          int menuItemTitleResourceId )
    {
    mBackgroundColourResourceId = backgroundColourResourceId;
    mIconResourceId             = iconResourceId;
    mLabelResourceId            = labelResourceId;
    mMenuItemId                 = menuItemId;
    mMenuItemTitleResourceId    = menuItemTitleResourceId;
    }


  /*****************************************************
   *
   * Returns the resource id of the background colour that
   * represents this image source.
   *
   *****************************************************/
  int getBackgroundColourResourceId()
    {
    return ( mBackgroundColourResourceId );
    }


  /*****************************************************
   *
   * Returns the resource id of the icon that represents
   * this image source.
   *
   *****************************************************/
  int getIconResourceId()
    {
    return ( mIconResourceId );
    }


  /*****************************************************
   *
   * Returns the resource id of the label string that
   * represents this image source.
   *
   *****************************************************/
  int getLabelResourceId()
    {
    return ( mLabelResourceId );
    }


  /*****************************************************
   *
   * Returns the id of the menu item for this image source.
   *
   *****************************************************/
  public int getMenuItemId()
    {
    return ( mMenuItemId );
    }


  /*****************************************************
   *
   * Adds this image source as a menu item. The order is
   * the same as the request code.
   *
   *****************************************************/
  public void addMenuItem( Menu menu )
    {
    menu.add( 0, mMenuItemId, mActivityRequestCode, mMenuItemTitleResourceId );
    }


  /*****************************************************
   *
   * Sets the activity request code. Should not normally
   * need to be set, as the Kite SDK does this automatically.
   *
   *****************************************************/
  public void setActivityRequestCode( int requestCode )
    {
    mActivityRequestCode = requestCode;
    }


  /*****************************************************
   *
   * Returns the activity request code.
   *
   *****************************************************/
  public int getActivityRequestCode()
    {
    return ( mActivityRequestCode );
    }


  /*****************************************************
   *
   * Returns true if this image source is available.
   *
   *****************************************************/
  abstract public boolean isAvailable( Context context );


  /*****************************************************
   *
   * Called when this image source is clicked.
   *
   *****************************************************/
  abstract public void onPick( Fragment fragment, int maxImageCount );


  /*****************************************************
   *
   * Called when this image source is clicked.
   *
   *****************************************************/
  public void onPick( Fragment fragment )
    {
    onPick( fragment, UNLIMITED_NO_OF_IMAGES );
    }


  /*****************************************************
   *
   * Called when this image source is clicked.
   *
   *****************************************************/
  public void onPick( Fragment fragment, boolean selectSingleImage )
    {
    onPick( fragment, ( selectSingleImage ? 1 : UNLIMITED_NO_OF_IMAGES ) );
    }


  /*****************************************************
   *
   * Returns picked photos as assets. May call back to the
   * consumer asynchronously or synchronously (i.e. from
   * within this method).
   *
   *****************************************************/
  abstract public void getAssetsFromPickerResult( Activity activity, Intent data, IAssetConsumer assetConsumer );


  ///// Inner class(es) /////

  /*****************************************************
   *
   * An asset consumer.
   *
   *****************************************************/
  public interface IAssetConsumer
    {
    public void isacOnAssets( List<Asset> assetList );
    }

  }
